const { app } = require('@azure/functions');

/**
 * Repository scanning endpoint for the Azure Function App
 */
app.http('scanRepo', {
    methods: ['POST'],
    authLevel: 'anonymous',
    route: 'scan',
    handler: async (request, context) => {
        context.log('Scan repository requested');
        
        try {
            const body = await request.json();
            const { repoUrl } = body;
            
            if (!repoUrl) {
                return {
                    status: 400,
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ error: 'Repository URL is required' })
                };
            }
            
            // Mock scan results for demo
            const mockResults = {
                repoUrl,
                scanDate: new Date().toISOString(),
                status: 'completed',
                findings: [
                    {
                        type: 'potential_secret',
                        severity: 'high',
                        file: 'config/database.js',
                        line: 23,
                        message: 'Potential database password found',
                        pattern: 'password=',
                        value: '••••••••••••'
                    },
                    {
                        type: 'api_key',
                        severity: 'medium',
                        file: 'src/services/api.js',
                        line: 15,
                        message: 'Potential API key detected',
                        pattern: 'api_key=',
                        value: '••••••••••••'
                    }
                ],
                summary: {
                    totalFiles: 147,
                    scannedFiles: 147,
                    secretsFound: 2,
                    highSeverity: 1,
                    mediumSeverity: 1,
                    lowSeverity: 0
                }
            };
            
            return {
                status: 200,
                headers: {
                    'Content-Type': 'application/json',
                    'Access-Control-Allow-Origin': '*',
                    'Access-Control-Allow-Methods': 'POST, OPTIONS',
                    'Access-Control-Allow-Headers': 'Content-Type'
                },
                body: JSON.stringify(mockResults)
            };
            
        } catch (error) {
            context.log.error('Error scanning repository:', error);
            return {
                status: 500,
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ error: 'Internal server error' })
            };
        }
    }
});
