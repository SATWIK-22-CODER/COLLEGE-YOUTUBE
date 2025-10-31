
#!/usr/bin/env bash
# college-youtube-starter-scaffold.sh
# Run this script in an empty directory to scaffold a combined frontend+backend project
# Usage: bash college-youtube-starter-scaffold.sh
set -e

echo "Creating scaffold for College YouTube (frontend + backend + infra)"

# Create folders
mkdir -p college-youtube/{backend/src/{controllers,middleware,models,services,routes},frontend/src/components,infra}
cd college-youtube

# root README
cat > README.md <<'EOF'
# College YouTube — Full Starter Scaffold

This scaffold contains a minimal but runnable starter for a combined frontend (React + Vite + Tailwind) and backend (Node.js + Express + Mongoose) project with Docker compose for local dev.

Run locally (dev):
  1. Install Docker and Docker Compose.
  2. From repo root run: docker-compose up --build

This scaffold is intentionally simple — extend models, security, and production settings before using in production.
EOF

# docker-compose
cat > docker-compose.yml <<'EOF'
version: '3.8'
services:
  mongo:
    image: mongo:6
    restart: unless-stopped
    volumes:
      - mongo-data:/data/db
  backend:
    build: ./backend
    env_file: ./backend/.env.dev
    ports:
      - "4000:4000"
    depends_on:
      - mongo
  frontend:
    build: ./frontend
    ports:
      - "3000:3000"
    depends_on:
      - backend
volumes:
  mongo-data:
EOF

# Backend package.json
cat > backend/package.json <<'EOF'
{
  "name": "college-youtube-backend",
  "version": "0.1.0",
  "main": "src/app.js",
  "scripts": {
    "start": "node src/app.js",
    "dev": "nodemon src/app.js"
  },
  "dependencies": {
    "aws-sdk": "^2.1360.0",
    "bcrypt": "^5.1.0",
    "body-parser": "^1.20.2",
    "bull": "^4.10.0",
    "cors": "^2.8.5",
    "dotenv": "^16.3.1",
    "express": "^4.18.2",
    "jsonwebtoken": "^9.0.0",
    "mongoose": "^7.5.0",
    "multer": "^1.4.5-lts.1"
  },
  "devDependencies": {
    "nodemon": "^2.0.22"
  }
}
EOF

# Backend .env.dev
cat > backend/.env.dev <<'EOF'
PORT=4000
MONGODB_URI=mongodb://mongo:27017/college_youtube
JWT_SECRET=dev_jwt_secret_change_me
S3_BUCKET=your-bucket
AWS_REGION=us-east-1
AWS_ACCESS_KEY_ID=
AWS_SECRET_ACCESS_KEY=
EOF

# Backend Dockerfile
cat > backend/Dockerfile <<'EOF'
FROM node:18-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --production || npm install
COPY . .
EXPOSE 4000
CMD ["node","src/app.js"]
EOF

# Backend app.js
cat > backend/src/app.js <<'EOF'
require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bodyParser = require('body-parser');
const authRoutes = require('./routes/auth.routes');
const videoRoutes = require('./routes/video.routes');
const analyticsRoutes = require('./routes/analytics.routes');

const app = express();
app.use(cors());
app.use(bodyParser.json());

// Routes
app.use('/api/v1/auth', authRoutes);
app.use('/api/v1/videos', videoRoutes);
app.use('/api/v1/analytics', analyticsRoutes);

// Simple health
app.get('/api/v1/health', (req,res)=>res.send({status:'ok', time: new Date()}));

const PORT = process.env.PORT || 4000;
mongoose.connect(process.env.MONGODB_URI, { useNewUrlParser:true, useUnifiedTopology:true }).then(()=>{
  app.listen(PORT, ()=>console.log('Backend running on', PORT));
}).catch(err=>{ console.error('Mongo connect failed', err); process.exit(1); });
EOF

# Backend models
cat > backend/src/models/User.js <<'EOF'
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const UserSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true },
  passwordHash: String,
  role: { type: String, enum: ['student','instructor','admin'], default: 'student' },
  createdAt: { type: Date, default: Date.now }
});
UserSchema.methods.verifyPassword = function(password){ return bcrypt.compare(password, this.passwordHash); };
module.exports = mongoose.model('User', UserSchema);
EOF

cat > backend/src/models/Video.js <<'EOF'
const mongoose = require('mongoose');
const VideoSchema = new mongoose.Schema({
  title: { type: String, required: true },
  description: String,
  storageUrl: String,
  captionsUrl: String,
  tags: [String],
  uploadedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  views: { type: Number, default: 0 },
  likes: { type: Number, default: 0 },
  createdAt: { type: Date, default: Date.now }
});
VideoSchema.index({ title: 'text', description: 'text', tags: 'text' });
module.exports = mongoose.model('Video', VideoSchema);
EOF

cat > backend/src/models/Comment.js <<'EOF'
const mongoose = require('mongoose');
const CommentSchema = new mongoose.Schema({
  video: { type: mongoose.Schema.Types.ObjectId, ref: 'Video' },
  author: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  text: String,
  parentId: { type: mongoose.Schema.Types.ObjectId, ref: 'Comment', default: null },
  createdAt: { type: Date, default: Date.now }
});
module.exports = mongoose.model('Comment', CommentSchema);
EOF

# Backend middleware
cat > backend/src/middleware/auth.middleware.js <<'EOF'
const jwt = require('jsonwebtoken');
const User = require('../models/User');
module.exports = async (req,res,next)=>{
  const h = req.headers.authorization;
  if(!h) return res.status(401).send({message:'no token'});
  const token = h.split(' ')[1];
  try{
    const p = jwt.verify(token, process.env.JWT_SECRET);
    req.user = await User.findById(p.id).select('-passwordHash');
    if(!req.user) return res.status(401).send({message:'invalid user'});
    next();
  }catch(e){ return res.status(401).send({message:'invalid token'}); }
}
EOF

cat > backend/src/middleware/role.middleware.js <<'EOF'
module.exports = (...allowed)=> (req,res,next)=>{
  if(!req.user) return res.status(401).end();
  if(!allowed.includes(req.user.role)) return res.status(403).send({message:'forbidden'});
  next();
}
EOF

# Backend controllers
cat > backend/src/controllers/auth.controller.js <<'EOF'
const User = require('../models/User');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
exports.register = async (req,res)=>{
  const { name,email,password,role } = req.body;
  const passHash = await bcrypt.hash(password, 10);
  const user = new User({ name, email, passwordHash: passHash, role });
  await user.save();
  res.status(201).send({ message:'registered' });
}
exports.login = async (req,res)=>{
  const { email, password } = req.body;
  const user = await User.findOne({ email });
  if(!user) return res.status(401).send({ message:'invalid' });
  const ok = await user.verifyPassword(password);
  if(!ok) return res.status(401).send({ message:'invalid' });
  const token = jwt.sign({ id: user._id, role: user.role }, process.env.JWT_SECRET, { expiresIn: '7d' });
  res.send({ token, user: { id: user._id, name: user.name, email: user.email, role: user.role } });
}
EOF

cat > backend/src/controllers/video.controller.js <<'EOF'
const Video = require('../models/Video');
// storage service is a placeholder; implement S3 or local storage
const multer = require('multer');
const upload = multer({ storage: multer.memoryStorage() });
exports.uploadMiddleware = upload.single('video');

exports.upload = async (req,res)=>{
  try{
    const { title, description, tags } = req.body;
    const file = req.file;
    // Simple local placeholder: write to ./uploads
    const fs = require('fs');
    const path = require('path');
    const outDir = path.join(__dirname,'..','..','uploads');
    if(!fs.existsSync(outDir)) fs.mkdirSync(outDir);
    const filename = `${Date.now()}_${file.originalname}`;
    fs.writeFileSync(path.join(outDir, filename), file.buffer);
    const storageUrl = `/uploads/${filename}`;
    const video = new Video({ title, description, storageUrl, tags: tags?tags.split(',').map(t=>t.trim()):[], uploadedBy: req.user._id });
    await video.save();
    // TODO: enqueue transcription job
    res.status(201).send(video);
  }catch(e){ console.error(e); res.status(500).send({message:'upload failed'}); }
}

exports.get = async (req,res)=>{
  const v = await Video.findById(req.params.id).populate('uploadedBy','name email');
  if(!v) return res.status(404).send({message:'not found'});
  v.views = v.views + 1;
  await v.save();
  res.send(v);
}

exports.list = async (req,res)=>{
  const { q, tag, page=1, limit=12 } = req.query;
  const filter = {};
  if(q) filter.$text = { $search: q };
  if(tag) filter.tags = tag;
  const videos = await Video.find(filter).sort({ createdAt: -1 }).skip((page-1)*limit).limit(Number(limit));
  res.send({ data: videos });
}
EOF

cat > backend/src/controllers/analytics.controller.js <<'EOF'
const Video = require('../models/Video');
exports.overview = async (req,res)=>{
  const totalVideos = await Video.countDocuments();
  const totalViewsAgg = await Video.aggregate([{ $group: { _id: null, sum: { $sum: '$views' } } }]);
  const totalViews = (totalViewsAgg[0] && totalViewsAgg[0].sum) || 0;
  const activeUsers = 0; // placeholder
  res.send({ totalVideos, totalViews, activeUsers });
}
EOF

# Backend routes
cat > backend/src/routes/auth.routes.js <<'EOF'
const express = require('express');
const router = express.Router();
const ctrl = require('../controllers/auth.controller');
router.post('/register', ctrl.register);
router.post('/login', ctrl.login);
module.exports = router;
EOF

cat > backend/src/routes/video.routes.js <<'EOF'
const express = require('express');
const router = express.Router();
const ctrl = require('../controllers/video.controller');
const auth = require('../middleware/auth.middleware');
router.get('/', ctrl.list);
router.get('/:id', ctrl.get);
router.post('/', auth, ctrl.uploadMiddleware, ctrl.upload);
module.exports = router;
EOF

cat > backend/src/routes/analytics.routes.js <<'EOF'
const express = require('express');
const router = express.Router();
const ctrl = require('../controllers/analytics.controller');
const auth = require('../middleware/auth.middleware');
const role = require('../middleware/role.middleware');
router.get('/overview', auth, role('admin'), ctrl.overview);
module.exports = router;
EOF

# Simple uploads static server in backend (update app.js to serve uploads)
# Update app.js to add static serving (append)
cat >> backend/src/app.js <<'EOF'
const path = require('path');
app.use('/uploads', express.static(path.join(__dirname,'..','uploads')));
EOF

# Frontend using Vite + React + Tailwind minimal
cat > frontend/package.json <<'EOF'
{
  "name":"college-youtube-frontend",
  "version":"0.1.0",
  "private": true,
  "scripts": {
    "dev": "vite --port 3000",
    "build": "vite build",
    "preview": "vite preview --port 3000"
  },
  "dependencies": {
    "axios": "^1.5.0",
    "react": "^18.2.0",
    "react-dom": "^18.2.0",
    "react-router-dom": "^6.17.0"
  },
  "devDependencies": {
    "@vitejs/plugin-react": "^5.2.0",
    "vite": "^5.1.0"
  }
}
EOF

cat > frontend/Dockerfile <<'EOF'
FROM node:18-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --production || npm install
COPY . .
EXPOSE 3000
CMD ["npm","run","dev"]
EOF

cat > frontend/index.html <<'EOF'
<!doctype html>
<html>
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>College YouTube - Dev</title>
  </head>
  <body>
    <div id="root"></div>
    <script type="module" src="/src/main.jsx"></script>
  </body>
</html>
EOF

cat > frontend/src/main.jsx <<'EOF'
import React from 'react'
import { createRoot } from 'react-dom/client'
import { BrowserRouter, Routes, Route, Link } from 'react-router-dom'
import Home from './components/Home'
import Login from './components/Login'
import Upload from './components/Upload'
import VideoPlayer from './components/VideoPlayer'
import AdminDashboard from './components/AdminDashboard'

function App(){
  return (
    <BrowserRouter>
      <div style={{padding:20}}>
        <nav><Link to="/">Home</Link> | <Link to="/upload">Upload</Link> | <Link to="/admin">Admin</Link></nav>
        <Routes>
          <Route path="/" element={<Home/>} />
          <Route path="/login" element={<Login/>} />
          <Route path="/upload" element={<Upload/>} />
          <Route path="/watch/:id" element={<VideoPlayer/>} />
          <Route path="/admin" element={<AdminDashboard/>} />
        </Routes>
      </div>
    </BrowserRouter>
  )
}

createRoot(document.getElementById('root')).render(<App />)
EOF

cat > frontend/src/components/Home.jsx <<'EOF'
import React, { useEffect, useState } from 'react';
import axios from 'axios';
import { Link } from 'react-router-dom';
export default function Home(){
  const [videos,setVideos] = useState([]);
  useEffect(()=>{ axios.get('/api/v1/videos').then(r=>setVideos(r.data.data||[])).catch(()=>{}); },[]);
  return (
    <div>
      <h1>College YouTube - Home</h1>
      <div>
        {videos.map(v=> (
          <div key={v._id} style={{border:'1px solid #ddd', padding:10, margin:8}}>
            <h3>{v.title}</h3>
            <p>{v.description}</p>
            <Link to={`/watch/${v._id}`}>Watch</Link>
          </div>
        ))}
      </div>
    </div>
  )
}
EOF

cat > frontend/src/components/Login.jsx <<'EOF'
import React, { useState } from 'react';
import axios from 'axios';
import { useNavigate } from 'react-router-dom';
export default function Login(){
  const [email,setEmail]=useState('');
  const [password,setPassword]=useState('');
  const nav = useNavigate();
  const submit=async(e)=>{ e.preventDefault(); const r = await axios.post('/api/v1/auth/login',{email,password}); localStorage.setItem('token', r.data.token); nav('/'); }
  return (
    <form onSubmit={submit} style={{maxWidth:400}}>
      <h2>Login</h2>
      <input placeholder="Email" value={email} onChange={e=>setEmail(e.target.value)} />
      <br/>
      <input placeholder="Password" type="password" value={password} onChange={e=>setPassword(e.target.value)} />
      <br/>
      <button>Login</button>
    </form>
  )
}
EOF

cat > frontend/src/components/Upload.jsx <<'EOF'
import React, { useState } from 'react';
import axios from 'axios';
export default function Upload(){
  const [file,setFile]=useState(null);
  const [title,setTitle]=useState('');
  const upload=async(e)=>{
    e.preventDefault();
    const fd = new FormData(); fd.append('video', file); fd.append('title', title);
    const token = localStorage.getItem('token');
    await axios.post('/api/v1/videos', fd, { headers: { 'Content-Type': 'multipart/form-data', Authorization: `Bearer ${token}` } });
    alert('uploaded');
  }
  return (
    <form onSubmit={upload}>
      <h2>Upload</h2>
      <input value={title} onChange={e=>setTitle(e.target.value)} placeholder="Title" />
      <br/>
      <input type="file" accept="video/*" onChange={e=>setFile(e.target.files[0])} />
      <br/>
      <button>Upload</button>
    </form>
  )
}
EOF

cat > frontend/src/components/VideoPlayer.jsx <<'EOF'
import React, { useEffect, useState } from 'react';
import { useParams } from 'react-router-dom';
import axios from 'axios';
export default function VideoPlayer(){
  const { id } = useParams();
  const [video, setVideo] = useState(null);
  useEffect(()=>{ axios.get('/api/v1/videos/'+id).then(r=>setVideo(r.data)).catch(()=>{}); },[id]);
  if(!video) return <div>Loading...</div>;
  return (
    <div>
      <h2>{video.title}</h2>
      <video controls style={{maxWidth:'100%'}}>
        <source src={video.storageUrl} />
        {video.captionsUrl && <track kind="subtitles" src={video.captionsUrl} default />}
      </video>
      <p>{video.description}</p>
    </div>
  )
}
EOF

cat > frontend/src/components/AdminDashboard.jsx <<'EOF'
import React, { useEffect, useState } from 'react';
import axios from 'axios';
export default function AdminDashboard(){
  const [stats,setStats]=useState(null);
  useEffect(()=>{ const token = localStorage.getItem('token'); axios.get('/api/v1/analytics/overview', { headers:{ Authorization:`Bearer ${token}` } }).then(r=>setStats(r.data)).catch(()=>{}); },[]);
  return (
    <div>
      <h2>Admin Dashboard</h2>
      {stats ? (
        <div>
          <div>Total videos: {stats.totalVideos}</div>
          <div>Total views: {stats.totalViews}</div>
        </div>
      ) : <div>Loading...</div> }
    </div>
  )
}
EOF

# Vite config
cat > frontend/vite.config.js <<'EOF'
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
export default defineConfig({ plugins:[react()], server: { proxy: { '/api': 'http://backend:4000' } } })
EOF

# Done
cd ..

echo "Scaffold created in ./college-youtube"

echo "Next steps:"
echo "  cd college-youtube"
echo "  docker-compose up --build"
echo "Then open http://localhost:3000 for frontend and http://localhost:4000/api/v1/health for backend"

exit 0