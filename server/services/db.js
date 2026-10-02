const mongoose = require('mongoose');
const { v4: uuidv4 } = require('uuid');

let isConnected = false;
let memoryStore = {
  users: [],
  projects: [
    {
      _id: 'proj_default',
      name: 'Default Workspace',
      description: 'Primary API security audit project',
      owner: 'demo@apisentinel.dev',
      scanCount: 0,
      latestScore: 0,
      createdAt: new Date(),
      updatedAt: new Date()
    }
  ],
  scans: []
};

async function connectDB() {
  const uri = process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017/api-sentinel';
  try {
    mongoose.set('strictQuery', false);
    await mongoose.connect(uri, {
      serverSelectionTimeoutMS: 2000
    });
    isConnected = true;
    console.log('[API Sentinel] Connected to MongoDB Atlas / Local Database successfully.');
  } catch (err) {
    isConnected = false;
    console.warn(`[API Sentinel] MongoDB unavailable (${err.message}). Running in Resilient In-Memory Storage Mode.`);
  }
}

const dbStore = {
  isMongoConnected: () => isConnected,

  // Users
  async findUserByEmail(email) {
    if (isConnected) {
      const User = require('../models/User');
      return await User.findOne({ email: email.toLowerCase() });
    }
    return memoryStore.users.find(u => u.email.toLowerCase() === email.toLowerCase());
  },

  async createUser(userData) {
    if (isConnected) {
      const User = require('../models/User');
      return await User.create(userData);
    }
    const newUser = {
      _id: 'usr_' + uuidv4().slice(0, 8),
      ...userData,
      createdAt: new Date(),
      updatedAt: new Date()
    };
    memoryStore.users.push(newUser);
    return newUser;
  },

  // Projects
  async getProjects(owner) {
    if (isConnected) {
      const Project = require('../models/Project');
      return await Project.find().sort({ updatedAt: -1 });
    }
    return memoryStore.projects;
  },

  async createProject(projectData) {
    if (isConnected) {
      const Project = require('../models/Project');
      return await Project.create(projectData);
    }
    const newProj = {
      _id: 'proj_' + uuidv4().slice(0, 8),
      ...projectData,
      scanCount: 0,
      latestScore: 0,
      createdAt: new Date(),
      updatedAt: new Date()
    };
    memoryStore.projects.unshift(newProj);
    return newProj;
  },

  // Scans
  async getScans(projectId = null) {
    if (isConnected) {
      const Scan = require('../models/Scan');
      const query = projectId ? { projectId } : {};
      return await Scan.find(query).sort({ createdAt: -1 });
    }
    if (projectId) {
      return memoryStore.scans.filter(s => s.projectId === projectId);
    }
    return memoryStore.scans;
  },

  async getScanById(scanId) {
    if (isConnected) {
      const Scan = require('../models/Scan');
      return await Scan.findById(scanId);
    }
    return memoryStore.scans.find(s => s._id === scanId || s.id === scanId);
  },

  async createScan(scanData) {
    if (isConnected) {
      const Scan = require('../models/Scan');
      const created = await Scan.create(scanData);
      
      // Update project counters if project exists
      if (scanData.projectId) {
        const Project = require('../models/Project');
        await Project.findByIdAndUpdate(scanData.projectId, {
          $inc: { scanCount: 1 },
          latestScore: scanData.riskScore,
          updatedAt: new Date()
        });
      }
      return created;
    }
    const newScan = {
      _id: 'scn_' + uuidv4().slice(0, 8),
      id: 'scn_' + uuidv4().slice(0, 8),
      ...scanData,
      createdAt: new Date(),
      completedAt: new Date()
    };
    memoryStore.scans.unshift(newScan);

    // Update memory project
    const proj = memoryStore.projects.find(p => p._id === scanData.projectId || p.id === scanData.projectId);
    if (proj) {
      proj.scanCount = (proj.scanCount || 0) + 1;
      proj.latestScore = scanData.riskScore;
      proj.updatedAt = new Date();
    }
    return newScan;
  },

  async deleteScan(scanId) {
    if (isConnected) {
      const Scan = require('../models/Scan');
      return await Scan.findByIdAndDelete(scanId);
    }
    const idx = memoryStore.scans.findIndex(s => s._id === scanId || s.id === scanId);
    if (idx !== -1) {
      return memoryStore.scans.splice(idx, 1)[0];
    }
    return null;
  }
};

module.exports = { connectDB, dbStore };
