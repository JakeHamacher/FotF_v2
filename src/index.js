import { Router } from 'itty-router';
import { jwtVerify, SignJWT } from 'jose';
import { nanoid } from 'nanoid';

const router = Router();

// Auth middleware
async function verifyAuth(request, env) {
    const cookie = request.headers.get('Cookie');
    if (!cookie) return null;
    
    const match = cookie.match(/SESSION=([^;]+)/);
    if (!match) return null;
    
    try {
        const secret = new TextEncoder().encode(env.SESSION_JWT_SECRET);
        const { payload } = await jwtVerify(match[1], secret);
        return payload;
    } catch (err) {
        return null;
    }
}

// Admin middleware
function requireAdmin(user) {
    if (!user || !user.is_admin) {
        return new Response('Forbidden', { status: 403 });
    }
    return null;
}

// Auth routes
router.get('/api/auth/login', async (request, env) => {
    const state = nanoid();
    const redirectUri = new URL(request.url).origin + '/api/auth/callback';
    
    const authUrl = new URL(env.OAUTH_AUTH_URL);
    authUrl.searchParams.set('client_id', env.OAUTH_CLIENT_ID);
    authUrl.searchParams.set('redirect_uri', redirectUri);
    authUrl.searchParams.set('response_type', 'code');
    authUrl.searchParams.set('scope', 'openid profile email');
    authUrl.searchParams.set('state', state);
    
    return Response.redirect(authUrl.toString());
});

router.get('/api/auth/callback', async (request, env) => {
    const { code, state } = request.query;
    if (!code) return new Response('Missing code', { status: 400 });
    
    // Exchange code for tokens
    const redirectUri = new URL(request.url).origin + '/api/auth/callback';
    const tokenResponse = await fetch(env.OAUTH_TOKEN_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
            grant_type: 'authorization_code',
            client_id: env.OAUTH_CLIENT_ID,
            client_secret: env.OAUTH_CLIENT_SECRET,
            code,
            redirect_uri: redirectUri,
        }),
    });
    
    const tokens = await tokenResponse.json();
    if (!tokenResponse.ok) return new Response('Token exchange failed', { status: 400 });
    
    // Get user info
    const userResponse = await fetch(env.OAUTH_USERINFO_URL, {
        headers: { Authorization: `Bearer ${tokens.access_token}` },
    });
    const userInfo = await userResponse.json();
    
    // Determine if admin
    const adminWhitelist = env.ADMIN_WHITELIST.split(',');
    const is_admin = adminWhitelist.includes(userInfo.email);
    
    // Create or update user
    const userId = `${userInfo.iss}|${userInfo.sub}`;
    await env.DB.prepare(`
        INSERT OR REPLACE INTO users (id, provider, email, name)
        VALUES (?, ?, ?, ?)
    `).bind(userId, userInfo.iss, userInfo.email, userInfo.name).run();
    
    // Create JWT
    const secret = new TextEncoder().encode(env.SESSION_JWT_SECRET);
    const jwt = await new SignJWT({
        sub: userId,
        email: userInfo.email,
        name: userInfo.name,
        is_admin,
    })
        .setProtectedHeader({ alg: 'HS256' })
        .setExpirationTime('24h')
        .sign(secret);
    
    // Set cookie
    const response = Response.redirect(new URL(request.url).origin);
    response.headers.append('Set-Cookie', 
        `SESSION=${jwt}; HttpOnly; Secure; SameSite=Strict; Path=/`
    );
    return response;
});

router.get('/api/me', async (request, env) => {
    const user = await verifyAuth(request, env);
    if (!user) return new Response(null, { status: 401 });
    return Response.json(user);
});

router.post('/api/auth/logout', async () => {
    const response = new Response(null, { status: 204 });
    response.headers.set('Set-Cookie', 'SESSION=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0');
    return response;
});

// Search endpoint
router.get('/api/search', async (request, env) => {
    const { q, tags, author, language, sort = 'rank', limit = 20, cursor } = request.query;
    
    let whereClauses = [];
    let params = [];
    
    if (q) {
        whereClauses.push('documents_fts MATCH ?');
        params.push(q);
    }
    if (tags) {
        const tagList = tags.split(',');
        whereClauses.push(`EXISTS (
            SELECT 1 FROM document_tags dt 
            WHERE dt.document_id = documents.id AND dt.tag IN (${tagList.map(() => '?').join(',')})
        )`);
        params.push(...tagList);
    }
    if (author) {
        whereClauses.push('documents.author LIKE ?');
        params.push(`%${author}%`);
    }
    if (language) {
        whereClauses.push('documents.language = ?');
        params.push(language);
    }
    
    // Add visibility check
    whereClauses.push('(documents.visibility = "public" OR documents.status = "ready")');
    
    const where = whereClauses.length ? `WHERE ${whereClauses.join(' AND ')}` : '';
    
    // Handle pagination
    let pagination = '';
    if (cursor) {
        // This is a simplification; actual implementation depends on sort strategy
        pagination = 'AND documents.id > ?';
        params.push(cursor);
    }
    
    const query = `
        SELECT documents.*, bm25(documents_fts) as rank 
        FROM documents 
        JOIN documents_fts ON documents.id = documents_fts.rowid 
        ${where} ${pagination}
        ORDER BY ${sort === 'rank' ? 'rank' : 'documents.created_at DESC'} 
        LIMIT ?
    `;
    params.push(parseInt(limit));
    
    const result = await env.DB.prepare(query).bind(...params).all();
    return Response.json({
        documents: result.results,
        cursor: result.results.length > 0 ? result.results[result.results.length - 1].id : null
    });
});

// Add other routes here...

export default {
    async fetch(request, env, ctx) {
        return router.handle(request, env, ctx).catch(err => {
            return new Response('Internal Server Error', { status: 500 });
        });
    },
};
