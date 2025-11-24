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

// Document view
router.get('/api/docs/:id', async (request, env) => {
    const { id } = request.params;
    const user = await verifyAuth(request, env);
    
    const doc = await env.DB.prepare(`
        SELECT * FROM documents WHERE id = ?
    `).bind(id).first();
    
    if (!doc) return new Response('Not found', { status: 404 });
    
    // Check visibility
    if (doc.visibility === 'private' && (!user || user.sub !== doc.created_by)) {
        return new Response('Forbidden', { status: 403 });
    }
    
    // Generate signed URL for download
    const url = await env.MY_R2.getSignedUrl(doc.r2_key, { expiresIn: 3600 });
    
    return Response.json({
        ...doc,
        download_url: url
    });
});

// Favorites
router.get('/api/user/favorites', async (request, env) => {
    const user = await verifyAuth(request, env);
    if (!user) return new Response(null, { status: 401 });
    
    const favorites = await env.DB.prepare(`
        SELECT d.* FROM favorites f
        JOIN documents d ON f.document_id = d.id
        WHERE f.user_id = ?
    `).bind(user.sub).all();
    
    return Response.json(favorites.results);
});

router.post('/api/user/favorites', async (request, env) => {
    const user = await verifyAuth(request, env);
    if (!user) return new Response(null, { status: 401 });
    
    const { document_id } = await request.json();
    await env.DB.prepare(`
        INSERT OR IGNORE INTO favorites (user_id, document_id)
        VALUES (?, ?)
    `).bind(user.sub, document_id).run();
    
    return new Response(null, { status: 204 });
});

router.delete('/api/user/favorites/:document_id', async (request, env) => {
    const user = await verifyAuth(request, env);
    if (!user) return new Response(null, { status: 401 });
    
    const { document_id } = request.params;
    await env.DB.prepare(`
        DELETE FROM favorites WHERE user_id = ? AND document_id = ?
    `).bind(user.sub, document_id).run();
    
    return new Response(null, { status: 204 });
});

// Notes
router.get('/api/docs/:id/notes', async (request, env) => {
    const user = await verifyAuth(request, env);
    if (!user) return new Response(null, { status: 401 });
    
    const { id } = request.params;
    const notes = await env.DB.prepare(`
        SELECT * FROM notes 
        WHERE document_id = ? AND (user_id = ? OR visibility = 'shared')
    `).bind(id, user.sub).all();
    
    return Response.json(notes.results);
});

router.post('/api/docs/:id/notes', async (request, env) => {
    const user = await verifyAuth(request, env);
    if (!user) return new Response(null, { status: 401 });
    
    const { id } = request.params;
    const { content, visibility = 'private' } = await request.json();
    const noteId = nanoid();
    
    await env.DB.prepare(`
        INSERT INTO notes (id, user_id, document_id, content, visibility)
        VALUES (?, ?, ?, ?, ?)
    `).bind(noteId, user.sub, id, content, visibility).run();
    
    return Response.json({ id: noteId });
});

router.put('/api/notes/:id', async (request, env) => {
    const user = await verifyAuth(request, env);
    if (!user) return new Response(null, { status: 401 });
    
    const { id } = request.params;
    const { content, visibility } = await request.json();
    
    // Check ownership
    const note = await env.DB.prepare(`
        SELECT * FROM notes WHERE id = ? AND user_id = ?
    `).bind(id, user.sub).first();
    
    if (!note) return new Response('Not found', { status: 404 });
    
    await env.DB.prepare(`
        UPDATE notes SET content = ?, visibility = ?, updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
    `).bind(content, visibility, id).run();
    
    return new Response(null, { status: 204 });
});

router.delete('/api/notes/:id', async (request, env) => {
    const user = await verifyAuth(request, env);
    if (!user) return new Response(null, { status: 401 });
    
    const { id } = request.params;
    
    // Check ownership
    const result = await env.DB.prepare(`
        DELETE FROM notes WHERE id = ? AND user_id = ?
    `).bind(id, user.sub).run();
    
    if (result.changes === 0) return new Response('Not found', { status: 404 });
    return new Response(null, { status: 204 });
});

// Admin upload
router.post('/api/admin/upload', async (request, env) => {
    const user = await verifyAuth(request, env);
    if (!user) return new Response(null, { status: 401 });
    
    const adminCheck = requireAdmin(user);
    if (adminCheck) return adminCheck;
    
    // Rate limiting
    const rateLimitKey = `upload:${user.sub}`;
    const rateLimit = await env.KV_RATE_LIMIT.get(rateLimitKey);
    if (rateLimit && parseInt(rateLimit) > 5) {
        return new Response('Rate limit exceeded', { status: 429 });
    }
    
    // Process multipart upload
    const formData = await request.formData();
    const file = formData.get('file');
    if (!file) return new Response('No file', { status: 400 });
    
    const r2Key = nanoid();
    await env.MY_R2.put(r2Key, file.stream(), {
        httpMetadata: { contentType: file.type }
    });
    
    // Update rate limit
    await env.KV_RATE_LIMIT.put(rateLimitKey, '1', { expirationTtl: 3600 });
    
    return Response.json({ r2_key: r2Key });
});

// Admin create document
router.post('/api/docs', async (request, env) => {
    const user = await verifyAuth(request, env);
    if (!user) return new Response(null, { status: 401 });
    
    const adminCheck = requireAdmin(user);
    if (adminCheck) return adminCheck;
    
    const data = await request.json();
    const id = nanoid();
    
    await env.DB.prepare(`
        INSERT INTO documents (id, title, summary, author, language, tags, topics, 
                              r2_key, mime_type, size_bytes, visibility, created_by)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
        id, data.title, data.summary, data.author, data.language, 
        JSON.stringify(data.tags || []), data.topics, data.r2_key, 
        data.mime_type, data.size_bytes, data.visibility || 'public', user.sub
    ).run();
    
    // Insert tags
    if (data.tags) {
        for (const tag of data.tags) {
            await env.DB.prepare(`
                INSERT INTO document_tags (document_id, tag) VALUES (?, ?)
            `).bind(id, tag).run();
        }
    }
    
    // Trigger extraction
    if (env.EXTRACTION_WEBHOOK) {
        await fetch(env.EXTRACTION_WEBHOOK, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ document_id: id, r2_key: data.r2_key })
        });
    }
    
    return Response.json({ id });
});

export default {
    async fetch(request, env, ctx) {
        return router.handle(request, env, ctx).catch(err => {
            console.error(err);
            return new Response('Internal Server Error', { status: 500 });
        });
    },
};
