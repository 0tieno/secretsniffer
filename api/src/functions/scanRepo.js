const { app } = require('@azure/functions');
const simpleGit = require('simple-git');
const fs = require('fs').promises;
const path = require('path');
const tmp = require('tmp');
const { spawn } = require('child_process');

/**
 * Azure Function to scan GitHub repositories for secrets using Gitleaks
 * Implements security best practices with proper error handling and logging
 */
app.http('scanRepo', {
    methods: ['GET', 'POST'],
    authLevel: 'anonymous',
    route: 'scan',
    handler: async (request, context) => {
        context.log('Starting repository scan request');
        
        // Enable CORS for frontend
        const corsHeaders = {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
            'Access-Control-Allow-Headers': 'Content-Type, Authorization',
            'Content-Type': 'application/json'
        };

        // Handle preflight OPTIONS request
        if (request.method === 'OPTIONS') {
            return {
                status: 200,
                headers: corsHeaders,
                body: ''
            };
        }

        try {
            // Extract repository URL from request
            let repoUrl;
            if (request.method === 'POST') {
                const body = await request.json();
                repoUrl = body.repoUrl;
            } else {
                // Fix: Use request.query.repoUrl instead of request.query.get('repoUrl')
                repoUrl = request.query.repoUrl;
            }

            // Validate input
            if (!repoUrl) {
                context.log('No repository URL provided');
                return {
                    status: 400,
                    headers: corsHeaders,
                    body: JSON.stringify({ 
                        error: 'Repository URL is required',
                        message: 'Please provide a valid GitHub repository URL'
                    })
                };
            }

            // Validate GitHub URL format
            if (!repoUrl.includes('github.com')) {
                context.log(`Invalid repository URL: ${repoUrl}`);
                return {
                    status: 400,
                    headers: corsHeaders,
                    body: JSON.stringify({ 
                        error: 'Invalid repository URL',
                        message: 'Please provide a valid GitHub repository URL'
                    })
                };
            }

            context.log(`Processing repository: ${repoUrl}`);

            // Create temporary directory for cloning
            const tmpDir = await createTempDirectory();
            context.log(`Created temporary directory: ${tmpDir}`);

            try {
                // Clone repository
                await cloneRepository(repoUrl, tmpDir, context);
                
                // Run Gitleaks scan
                const scanResults = await runGitleaksScan(tmpDir, context);
                
                // Process and format results
                const formattedResults = await formatScanResults(scanResults, repoUrl, context);
                
                context.log(`Scan completed successfully. Found ${formattedResults.totalSecrets} secrets`);
                
                return {
                    status: 200,
                    headers: corsHeaders,
                    body: JSON.stringify(formattedResults)
                };

            } finally {
                // Cleanup temporary directory
                await cleanupTempDirectory(tmpDir, context);
            }

        } catch (error) {
            context.log('Error during repository scan:', error);
            context.log('Error stack:', error.stack);
            return {
                status: 500,
                headers: corsHeaders,
                body: JSON.stringify({
                    error: 'Internal server error',
                    message: 'Failed to scan repository. Please try again later.',
                    details: process.env.NODE_ENV === 'development' ? (error.stack || error.message) : undefined
                })
            };
        }
    }
});


/**
 * Create a temporary directory for repository cloning
 */
async function createTempDirectory() {
    return new Promise((resolve, reject) => {
        tmp.dir({ unsafeCleanup: true }, (err, path) => {
            if (err) reject(err);
            else resolve(path);
        });
    });
}

/**
 * Clone repository to temporary directory
 */
async function cloneRepository(repoUrl, tmpDir, context) {
    try {
        const git = simpleGit();
        
        // For private repos, you would use GitHub token here
        // const authUrl = repoUrl.replace('https://github.com/', `https://${process.env.GITHUB_TOKEN}@github.com/`);
        
        context.log(`Cloning repository to ${tmpDir}`);
        await git.clone(repoUrl, tmpDir, ['--depth', '50']); // Shallow clone for performance
        
        context.log('Repository cloned successfully');
    } catch (error) {
        context.log('Failed to clone repository:', error);
        throw new Error(`Failed to clone repository: ${error.message}`);
    }
}

/**
 * Run Gitleaks scan on the cloned repository using Docker
 */
async function runGitleaksScan(repoPath, context) {
    return new Promise((resolve, reject) => {
        context.log('Starting Gitleaks scan via Docker');
        const gitleaksImage = 'zricethez/gitleaks:latest';
        const args = [
            'run',
            '--rm',
            '-v', `${repoPath}:/repo`,
            gitleaksImage,
            'detect',
            '--source', '/repo',
            '--report-format', 'json'
        ];
        const scanTimeoutMs = 60 * 1000; // 1 minute timeout

        let output = '';
        let errorOutput = '';
        let timedOut = false;

        const dockerProcess = spawn('docker', args);

        const timeout = setTimeout(() => {
            timedOut = true;
            dockerProcess.kill();
            context.log('Gitleaks scan timed out');
            reject(new Error('Gitleaks scan timed out'));
        }, scanTimeoutMs);

        dockerProcess.stdout.on('data', (data) => {
            output += data.toString();
        });

        dockerProcess.stderr.on('data', (data) => {
            errorOutput += data.toString();
        });

        dockerProcess.on('close', (code) => {
            clearTimeout(timeout);
            if (timedOut) return;
            context.log(`Gitleaks Docker process exited with code ${code}`);
            if (code === 0) {
                // No secrets found
                resolve('[]');
            } else if (code === 1) {
                // Secrets found
                resolve(output);
            } else {
                context.log('Gitleaks Docker error output:', errorOutput);
                reject(new Error(`Gitleaks Docker scan failed with code ${code}: ${errorOutput}`));
            }
        });

        dockerProcess.on('error', (error) => {
            clearTimeout(timeout);
            context.log('Failed to start Docker process:', error);
            reject(new Error(`Failed to start Docker: ${error.message}`));
        });
    });
}

/**
 * Format scan results for frontend consumption
 */
async function formatScanResults(scanOutput, repoUrl, context) {
    try {
        const findings = JSON.parse(scanOutput);
        // Sanitize repoName extraction
        let repoName = '';
        try {
            const urlParts = repoUrl.split('/');
            repoName = urlParts[urlParts.length - 1].replace(/\.git$/, '') || urlParts[urlParts.length - 2];
        } catch {
            repoName = 'unknown';
        }
        // Map Gitleaks output to our format
        const formattedFindings = findings.map((finding, index) => ({
            id: index + 1,
            file: finding.File,
            commit: finding.Commit.substring(0, 7), // Short commit hash
            secretType: mapSecretType(finding.Description, finding.RuleID),
            severity: determineSeverity(finding.Description, finding.RuleID),
            lineNumber: finding.StartLine,
            snippet: finding.Match,
            entropy: finding.Entropy,
            author: finding.Author,
            date: finding.Date
        }));

        return {
            repoName,
            totalSecrets: formattedFindings.length,
            scanDate: new Date().toISOString(),
            findings: formattedFindings,
            scanEngine: 'Gitleaks',
            version: '8.18.0'
        };

    } catch (error) {
        context.log('Failed to parse scan results:', error);
        throw new Error('Failed to process scan results');
    }
}

/**
 * Map Gitleaks rule descriptions to user-friendly secret types
 */
function mapSecretType(description, ruleId) {
    const typeMap = {
        'generic-api-key': 'API Key',
        'aws-access-token': 'AWS Access Key',
        'github-pat': 'GitHub Token',
        'slack-bot-token': 'Slack Bot Token',
        'discord-bot-token': 'Discord Bot Token',
        'database-password': 'Database Password',
        'private-key': 'Private Key',
        'jwt': 'JWT Token'
    };

    return typeMap[ruleId] || description || 'Unknown Secret';
}

/**
 * Determine severity based on secret type
 */
function determineSeverity(description, ruleId) {
    const highSeverityPatterns = ['private-key', 'aws-access-token', 'database-password'];
    const mediumSeverityPatterns = ['api-key', 'github-pat', 'jwt'];
    
    const desc = (description + ' ' + ruleId).toLowerCase();
    
    if (highSeverityPatterns.some(pattern => desc.includes(pattern))) {
        return 'high';
    } else if (mediumSeverityPatterns.some(pattern => desc.includes(pattern))) {
        return 'medium';
    } else {
        return 'low';
    }
}

/**
 * Cleanup temporary directory
 */
async function cleanupTempDirectory(tmpDir, context) {
    try {
        await fs.rm(tmpDir, { recursive: true, force: true });
        context.log(`Cleaned up temporary directory: ${tmpDir}`);
    } catch (error) {
        context.log('Failed to cleanup temporary directory:', error);
        // Don't throw here as cleanup failure shouldn't fail the request
    }
}
