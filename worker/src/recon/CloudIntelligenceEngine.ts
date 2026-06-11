import axios from 'axios';

export interface CloudIntelligence {
  provider: string;
  services: string[];
  buckets: string[];
  misconfigurations: string[];
}

export class CloudIntelligenceEngine {
  static async analyze(targetUrl: string, html: string, jsFiles: string[]): Promise<CloudIntelligence> {
    const intel: CloudIntelligence = {
      provider: 'Unknown',
      services: [],
      buckets: [],
      misconfigurations: []
    };

    // AWS Detectors
    if (html.includes('amazonaws.com') || jsFiles.some(f => f.includes('amazonaws.com'))) {
      intel.provider = 'AWS';
      
      const s3Regex = /https?:\/\/([^.]*)\.s3\.(?:[^.]*\.)?amazonaws\.com/g;
      const allText = html + ' ' + jsFiles.join(' ');
      
      for (const match of allText.matchAll(s3Regex)) {
        if (!intel.buckets.includes(match[1])) intel.buckets.push(match[1]);
      }
      
      if (allText.includes('cognito-idp')) intel.services.push('AWS Cognito');
      if (allText.includes('execute-api')) intel.services.push('API Gateway');
      if (allText.includes('appsync-api')) intel.services.push('AppSync (GraphQL)');
    }

    // Google Cloud Detectors
    if (html.includes('storage.googleapis.com') || allTextIncludes(jsFiles, html, 'storage.googleapis.com')) {
      if (intel.provider === 'Unknown') intel.provider = 'Google Cloud';
      const gcsRegex = /https?:\/\/storage\.googleapis\.com\/([^/"']+)/g;
      const allText = html + ' ' + jsFiles.join(' ');
      for (const match of allText.matchAll(gcsRegex)) {
         if (!intel.buckets.includes(match[1])) intel.buckets.push(match[1]);
      }
      intel.services.push('Cloud Storage');
    }

    if (allTextIncludes(jsFiles, html, 'firebaseio.com') || allTextIncludes(jsFiles, html, 'firebasestorage.googleapis.com')) {
       if (intel.provider === 'Unknown') intel.provider = 'Google Cloud (Firebase)';
       intel.services.push('Firebase Realtime DB / Storage');
    }

    // Azure Detectors
    if (allTextIncludes(jsFiles, html, 'blob.core.windows.net')) {
      if (intel.provider === 'Unknown') intel.provider = 'Microsoft Azure';
      intel.services.push('Azure Blob Storage');
      
      const azureRegex = /https?:\/\/([^.]+)\.blob\.core\.windows\.net/g;
      const allText = html + ' ' + jsFiles.join(' ');
      for (const match of allText.matchAll(azureRegex)) {
         if (!intel.buckets.includes(match[1])) intel.buckets.push(match[1]);
      }
    }

    // Verificar si algún bucket expuesto es público (Simple HEAD request)
    for (const bucket of intel.buckets) {
       let bucketUrl = '';
       if (intel.provider === 'AWS') bucketUrl = \`https://\${bucket}.s3.amazonaws.com\`;
       else if (intel.provider.includes('Google')) bucketUrl = \`https://storage.googleapis.com/\${bucket}\`;
       
       if (bucketUrl) {
         try {
           const res = await axios.head(bucketUrl, { timeout: 3000 });
           if (res.status === 200 || res.status === 403) { // 403 means it exists but we don't have list access. 200 means public!
             if (res.status === 200) intel.misconfigurations.push(\`Bucket público detectado: \${bucket}\`);
           }
         } catch(e) {}
       }
    }

    return intel;
  }
}

function allTextIncludes(arr: string[], text: string, search: string) {
  if (text.includes(search)) return true;
  return arr.some(a => a.includes(search));
}
