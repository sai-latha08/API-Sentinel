const { dbStore } = require('../services/db');

exports.getProjects = async (req, res, next) => {
  try {
    const owner = req.user ? req.user.email : 'demo@apisentinel.dev';
    const projects = await dbStore.getProjects(owner);
    res.json({ success: true, projects });
  } catch (err) {
    next(err);
  }
};

exports.createProject = async (req, res, next) => {
  try {
    const { name, description } = req.body;
    if (!name || !name.trim()) {
      return res.status(400).json({ error: 'Project name is required.' });
    }
    const owner = req.user ? req.user.email : 'demo@apisentinel.dev';
    const project = await dbStore.createProject({ name, description, owner });
    res.status(201).json({ success: true, project });
  } catch (err) {
    next(err);
  }
};
