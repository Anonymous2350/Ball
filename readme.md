# Chimera C2 Cloud Server

## Quick Deploy to Vercel

1. **Install Vercel CLI:**
   ```bash
   npm install -g vercel
   ```

2. **Deploy:**
   ```bash
   cd vercel-c2
   vercel --prod
   ```

3. **Get your URL:**
   After deployment, you'll get a URL like:
   ```
   https://your-project-name.vercel.app/api/command
   ```

4. **Use in APK Builder:**
   Enter this URL in the C2 server field when building your APK.

## Alternative: Netlify

For Netlify deployment:
1. Create account at netlify.com
2. Drag and drop the `vercel-c2` folder
3. Your URL will be: `https://your-site-name.netlify.app/api/command`

## Testing

Test your deployed server:
```bash
curl https://your-url.vercel.app/api/command
```

Should return: `{"status":"online","server":"Chimera C2","timestamp":"..."}`