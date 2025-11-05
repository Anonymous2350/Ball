@echo off
echo Deploying Chimera C2 to Vercel...
echo.

REM Install Vercel CLI if not installed
where vercel >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo Installing Vercel CLI...
    npm install -g vercel
)

REM Deploy to Vercel
echo Deploying...
vercel --prod

echo.
echo Deployment complete!
echo Your C2 server URL will be: https://your-project-name.vercel.app/api/command
pause