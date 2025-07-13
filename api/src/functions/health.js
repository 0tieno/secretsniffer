const { app } = require('@azure/functions');

/**
 * Health check endpoint for the Azure Function App
 */
app.http('health', {
    methods: ['GET'],
    authLevel: 'anonymous',
    route: 'health',
    handler: async (request, context) => {
        context.log('Health check requested');
        
        return {
            status: 200,
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                status: 'healthy',
                timestamp: new Date().toISOString(),
                service: 'GFaaS API',
                version: '1.0.0'
            })
        };
    }
});
