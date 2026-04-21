// ========================================
// LENEX HOSTING - COMPLETE SINGLE FILE
// Copy this entire code into server.js
// ========================================

import express from 'express';
import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import cors from 'cors';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = 5000;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// JWT Secret
const JWT_SECRET = 'lenexhost_super_secret_key_2026';

// ========================================
// MONGODB SCHEMAS
// ========================================

// User Schema
const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role: { type: String, enum: ['user', 'admin'], default: 'user' },
  createdAt: { type: Date, default: Date.now }
});

userSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  this.password = await bcrypt.hash(this.password, 10);
  next();
});

userSchema.methods.comparePassword = async function(password) {
  return await bcrypt.compare(password, this.password);
};

// Order Schema
const orderSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  plan: { type: String, required: true },
  price: { type: Number, required: true },
  status: { type: String, enum: ['pending', 'active', 'cancelled'], default: 'pending' },
  serverIp: String,
  serverPort: Number,
  createdAt: { type: Date, default: Date.now },
  expiresAt: Date
});

const User = mongoose.model('User', userSchema);
const Order = mongoose.model('Order', orderSchema);

// ========================================
// AUTH MIDDLEWARE
// ========================================

const auth = async (req, res, next) => {
  const token = req.header('Authorization')?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'Access denied' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.userId = decoded.userId;
    req.userRole = decoded.role;
    next();
  } catch (error) {
    res.status(401).json({ error: 'Invalid token' });
  }
};

const adminAuth = async (req, res, next) => {
  if (req.userRole !== 'admin') return res.status(403).json({ error: 'Admin only' });
  next();
};

// ========================================
// API ROUTES
// ========================================

// Register
app.post('/api/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;
    const existing = await User.findOne({ email });
    if (existing) return res.status(400).json({ error: 'Email already exists' });
    
    const user = new User({ name, email, password });
    await user.save();
    
    const token = jwt.sign({ userId: user._id, role: user.role }, JWT_SECRET);
    res.json({ token, user: { id: user._id, name: user.name, email: user.email, role: user.role } });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Login
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });
    
    const isValid = await user.comparePassword(password);
    if (!isValid) return res.status(401).json({ error: 'Invalid credentials' });
    
    const token = jwt.sign({ userId: user._id, role: user.role }, JWT_SECRET);
    res.json({ token, user: { id: user._id, name: user.name, email: user.email, role: user.role } });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get user profile
app.get('/api/me', auth, async (req, res) => {
  try {
    const user = await User.findById(req.userId).select('-password');
    res.json(user);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Create order
app.post('/api/orders', auth, async (req, res) => {
  try {
    const { plan, price } = req.body;
    const expiresAt = new Date();
    expiresAt.setMonth(expiresAt.getMonth() + 1);
    
    const order = new Order({
      userId: req.userId,
      plan,
      price,
      status: 'active',
      serverIp: `185.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`,
      serverPort: 25565 + Math.floor(Math.random() * 100),
      expiresAt
    });
    await order.save();
    res.json(order);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get user orders
app.get('/api/orders', auth, async (req, res) => {
  try {
    const orders = await Order.find({ userId: req.userId }).sort({ createdAt: -1 });
    res.json(orders);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get all orders (admin)
app.get('/api/admin/orders', auth, adminAuth, async (req, res) => {
  try {
    const orders = await Order.find().populate('userId', 'name email').sort({ createdAt: -1 });
    res.json(orders);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get all users (admin)
app.get('/api/admin/users', auth, adminAuth, async (req, res) => {
  try {
    const users = await User.find().select('-password');
    res.json(users);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Update order status (admin)
app.put('/api/admin/orders/:id', auth, adminAuth, async (req, res) => {
  try {
    const { status } = req.body;
    const order = await Order.findByIdAndUpdate(req.params.id, { status }, { new: true });
    res.json(order);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Delete user (admin)
app.delete('/api/admin/users/:id', auth, adminAuth, async (req, res) => {
  try {
    await User.findByIdAndDelete(req.params.id);
    await Order.deleteMany({ userId: req.params.id });
    res.json({ message: 'User deleted' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Stats (admin)
app.get('/api/admin/stats', auth, adminAuth, async (req, res) => {
  try {
    const totalUsers = await User.countDocuments();
    const totalOrders = await Order.countDocuments();
    const activeOrders = await Order.countDocuments({ status: 'active' });
    const totalRevenue = await Order.aggregate([{ $group: { _id: null, total: { $sum: '$price' } } }]);
    res.json({ totalUsers, totalOrders, activeOrders, totalRevenue: totalRevenue[0]?.total || 0 });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ========================================
// FRONTEND HTML (EMBEDDED)
// ========================================

const HTML = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Lenex Hosting - Minecraft & VPS Hosting</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://cdn.jsdelivr.net/npm/react@18.2.0/umd/react.development.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/react-dom@18.2.0/umd/react-dom.development.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/react-router-dom@6.20.0/umd/react-router-dom.development.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/axios/dist/axios.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/babel-standalone@6.26.0/babel.min.js"></script>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Inter', sans-serif; background: #0A0A0F; color: #FFFFFF; }
        .gradient-text { background: linear-gradient(135deg, #6C63FF, #8B80FF); -webkit-background-clip: text; background-clip: text; color: transparent; }
        .btn-gradient { background: linear-gradient(135deg, #6C63FF, #8B80FF); transition: all 0.3s; }
        .btn-gradient:hover { transform: translateY(-2px); box-shadow: 0 5px 20px rgba(108,99,255,0.4); }
        ::-webkit-scrollbar { width: 8px; }
        ::-webkit-scrollbar-track { background: #1A1A22; }
        ::-webkit-scrollbar-thumb { background: #6C63FF; border-radius: 10px; }
        .glow { text-shadow: 0 0 30px rgba(108,99,255,0.5); }
    </style>
</head>
<body>
    <div id="root"></div>
    
    <script type="text/babel">
        const { useState, useEffect } = React;
        const { createRoot } = ReactDOM;
        
        // API Helper
        const api = axios.create({ baseURL: '/api' });
        api.interceptors.request.use(config => {
            const token = localStorage.getItem('token');
            if (token) config.headers.Authorization = 'Bearer ' + token;
            return config;
        });
        
        // Components
        const Navbar = ({ user, onLogout }) => {
            const [menuOpen, setMenuOpen] = useState(false);
            return (
                <nav className="bg-[#0A0A0F]/95 backdrop-blur-md sticky top-0 z-50 border-b border-gray-800">
                    <div className="container mx-auto px-4 py-4">
                        <div className="flex justify-between items-center">
                            <a href="/" className="text-2xl font-bold">Lenex<span className="gradient-text">Host</span></a>
                            <div className="hidden md:flex items-center gap-8">
                                <a href="#home" className="text-gray-300 hover:text-primary transition">Home</a>
                                <a href="#plans" className="text-gray-300 hover:text-primary transition">Pricing</a>
                                {user ? (
                                    <>
                                        <a href="#dashboard" className="text-gray-300 hover:text-primary transition">Dashboard</a>
                                        <span className="text-gray-300">Welcome, {user.name}</span>
                                        <button onClick={onLogout} className="text-red-400 hover:text-red-300">Logout</button>
                                    </>
                                ) : (
                                    <>
                                        <a href="#login" className="text-gray-300 hover:text-primary transition">Login</a>
                                        <a href="#register" className="btn-gradient px-4 py-2 rounded-lg font-semibold">Sign Up</a>
                                    </>
                                )}
                            </div>
                        </div>
                    </div>
                </nav>
            );
        };
        
        const Plans = ({ onOrder, user }) => {
            const plans = [
                { name: 'Minecraft Basic', price: 499, ram: '2GB', slots: 'Unlimited', features: ['2GB RAM', 'Unlimited Slots', 'DDoS Protection', 'Free Subdomain'] },
                { name: 'Minecraft Pro', price: 999, ram: '6GB', slots: 'Unlimited', features: ['6GB RAM', 'Unlimited Slots', 'Priority Support', 'Free .com Domain'], popular: true },
                { name: 'VPS Starter', price: 1499, ram: '4GB', slots: '2 vCPU', features: ['2 vCPU Cores', '4GB RAM', '50GB NVMe', 'Root Access'] },
                { name: 'VPS Business', price: 2999, ram: '8GB', slots: '4 vCPU', features: ['4 vCPU Cores', '8GB RAM', '100GB NVMe', 'Dedicated IP'] }
            ];
            
            return (
                <div id="plans" className="py-20 bg-[#0F0F14]">
                    <div className="container mx-auto px-4">
                        <div className="text-center mb-12">
                            <h2 className="text-4xl md:text-5xl font-bold mb-4">Choose Your <span className="gradient-text">Plan</span></h2>
                            <p className="text-gray-400">High-performance hosting for all your needs</p>
                        </div>
                        <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-6">
                            {plans.map((plan, i) => (
                                <div key={i} className={\`bg-[#1A1A22] rounded-2xl p-6 border border-gray-800 hover:border-primary/50 transition-all hover:-translate-y-2 \${plan.popular ? 'ring-2 ring-primary' : ''}\`}>
                                    {plan.popular && <div className="absolute -top-3 left-1/2 transform -translate-x-1/2 bg-primary text-white px-4 py-1 rounded-full text-sm font-semibold">Most Popular</div>}
                                    <h3 className="text-xl font-bold mb-2">{plan.name}</h3>
                                    <div className="text-3xl font-bold text-primary mb-4">₹{plan.price}<span className="text-sm text-gray-400">/mo</span></div>
                                    <ul className="space-y-2 mb-6">
                                        {plan.features.map((f, j) => <li key={j} className="text-gray-300 text-sm">✓ {f}</li>)}
                                    </ul>
                                    <button onClick={() => onOrder(plan)} className="w-full bg-primary/20 hover:bg-primary text-primary hover:text-white border border-primary/50 rounded-lg py-2 font-semibold transition-all">
                                        Order Now
                                    </button>
                                </div>
                            ))}
                        </div>
                    </div>
                </div>
            );
        };
        
        const Features = () => {
            const features = [
                { icon: 'fa-microchip', title: 'High Performance', desc: 'Latest generation AMD EPYC & Intel Xeon processors' },
                { icon: 'fa-tachometer-alt', title: 'Low Latency', desc: 'Optimized network for minimal lag' },
                { icon: 'fa-shield-alt', title: 'Advanced Security', desc: 'Multi-layered security with real-time detection' },
                { icon: 'fa-sync-alt', title: 'Auto Recovery', desc: 'Automatic server recovery and backups' }
            ];
            return (
                <div className="py-20">
                    <div className="container mx-auto px-4">
                        <div className="text-center mb-12">
                            <h2 className="text-4xl md:text-5xl font-bold mb-4">We Won't <span className="gradient-text">Disappoint</span></h2>
                            <p className="text-gray-400">Advanced Features — Everything you need for professional hosting</p>
                        </div>
                        <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-6">
                            {features.map((f, i) => (
                                <div key={i} className="bg-[#1A1A22] rounded-2xl p-6 text-center border border-gray-800 hover:border-primary/50 transition-all">
                                    <i className={\`fas \${f.icon} text-4xl text-primary mb-4\`}></i>
                                    <h3 className="text-xl font-bold mb-2">{f.title}</h3>
                                    <p className="text-gray-400 text-sm">{f.desc}</p>
                                </div>
                            ))}
                        </div>
                    </div>
                </div>
            );
        };
        
        const Footer = () => (
            <footer className="bg-[#050508] py-8 text-center border-t border-gray-800">
                <div className="container mx-auto px-4">
                    <p className="text-gray-500">© 2026 Lenex Hosting. All rights reserved. | India's Fastest Growing Game Hosting Provider</p>
                </div>
            </footer>
        );
        
        const Login = ({ onLogin }) => {
            const [email, setEmail] = useState('');
            const [password, setPassword] = useState('');
            const [error, setError] = useState('');
            
            const handleSubmit = async (e) => {
                e.preventDefault();
                try {
                    const res = await api.post('/login', { email, password });
                    localStorage.setItem('token', res.data.token);
                    localStorage.setItem('user', JSON.stringify(res.data.user));
                    onLogin(res.data.user);
                } catch (err) {
                    setError(err.response?.data?.error || 'Login failed');
                }
            };
            
            return (
                <div className="min-h-screen flex items-center justify-center bg-[#0A0A0F] py-20">
                    <div className="bg-[#1A1A22] p-8 rounded-2xl w-full max-w-md border border-gray-800">
                        <h2 className="text-3xl font-bold text-center mb-6">Welcome <span className="gradient-text">Back</span></h2>
                        {error && <div className="bg-red-500/20 border border-red-500 text-red-400 p-3 rounded-lg mb-4">{error}</div>}
                        <form onSubmit={handleSubmit}>
                            <input type="email" placeholder="Email" value={email} onChange={e => setEmail(e.target.value)} className="w-full bg-[#0A0A0F] border border-gray-700 rounded-lg p-3 mb-4 text-white focus:outline-none focus:border-primary" required />
                            <input type="password" placeholder="Password" value={password} onChange={e => setPassword(e.target.value)} className="w-full bg-[#0A0A0F] border border-gray-700 rounded-lg p-3 mb-6 text-white focus:outline-none focus:border-primary" required />
                            <button type="submit" className="w-full btn-gradient py-3 rounded-lg font-semibold">Login</button>
                        </form>
                        <p className="text-center text-gray-400 mt-4">Don't have an account? <a href="#register" className="text-primary">Register</a></p>
                    </div>
                </div>
            );
        };
        
        const Register = ({ onLogin }) => {
            const [name, setName] = useState('');
            const [email, setEmail] = useState('');
            const [password, setPassword] = useState('');
            const [error, setError] = useState('');
            
            const handleSubmit = async (e) => {
                e.preventDefault();
                try {
                    const res = await api.post('/register', { name, email, password });
                    localStorage.setItem('token', res.data.token);
                    localStorage.setItem('user', JSON.stringify(res.data.user));
                    onLogin(res.data.user);
                } catch (err) {
                    setError(err.response?.data?.error || 'Registration failed');
                }
            };
            
            return (
                <div className="min-h-screen flex items-center justify-center bg-[#0A0A0F] py-20">
                    <div className="bg-[#1A1A22] p-8 rounded-2xl w-full max-w-md border border-gray-800">
                        <h2 className="text-3xl font-bold text-center mb-6">Create <span className="gradient-text">Account</span></h2>
                        {error && <div className="bg-red-500/20 border border-red-500 text-red-400 p-3 rounded-lg mb-4">{error}</div>}
                        <form onSubmit={handleSubmit}>
                            <input type="text" placeholder="Full Name" value={name} onChange={e => setName(e.target.value)} className="w-full bg-[#0A0A0F] border border-gray-700 rounded-lg p-3 mb-4 text-white focus:outline-none focus:border-primary" required />
                            <input type="email" placeholder="Email" value={email} onChange={e => setEmail(e.target.value)} className="w-full bg-[#0A0A0F] border border-gray-700 rounded-lg p-3 mb-4 text-white focus:outline-none focus:border-primary" required />
                            <input type="password" placeholder="Password" value={password} onChange={e => setPassword(e.target.value)} className="w-full bg-[#0A0A0F] border border-gray-700 rounded-lg p-3 mb-6 text-white focus:outline-none focus:border-primary" required />
                            <button type="submit" className="w-full btn-gradient py-3 rounded-lg font-semibold">Register</button>
                        </form>
                        <p className="text-center text-gray-400 mt-4">Already have an account? <a href="#login" className="text-primary">Login</a></p>
                    </div>
                </div>
            );
        };
        
        const Dashboard = ({ user }) => {
            const [orders, setOrders] = useState([]);
            const [loading, setLoading] = useState(true);
            
            useEffect(() => {
                api.get('/orders').then(res => { setOrders(res.data); setLoading(false); }).catch(() => setLoading(false));
            }, []);
            
            return (
                <div className="min-h-screen bg-[#0A0A0F] py-20">
                    <div className="container mx-auto px-4">
                        <h1 className="text-3xl font-bold mb-8">My <span className="gradient-text">Dashboard</span></h1>
                        <div className="bg-[#1A1A22] rounded-2xl p-6 border border-gray-800 mb-8">
                            <h2 className="text-xl font-semibold mb-4">Account Info</h2>
                            <p><span className="text-gray-400">Name:</span> {user?.name}</p>
                            <p><span className="text-gray-400">Email:</span> {user?.email}</p>
                            <p><span className="text-gray-400">Role:</span> {user?.role}</p>
                        </div>
                        <h2 className="text-2xl font-semibold mb-4">My Servers</h2>
                        {loading ? <p>Loading...</p> : orders.length === 0 ? <p className="text-gray-400">No active servers. Order one now!</p> : (
                            <div className="grid gap-4">
                                {orders.map(order => (
                                    <div key={order._id} className="bg-[#1A1A22] rounded-2xl p-6 border border-gray-800">
                                        <div className="flex justify-between items-start flex-wrap gap-4">
                                            <div>
                                                <h3 className="text-xl font-semibold text-primary">{order.plan}</h3>
                                                <p className="text-gray-400">IP: {order.serverIp}:{order.serverPort}</p>
                                                <p className="text-gray-400">Status: <span className={order.status === 'active' ? 'text-green-400' : 'text-yellow-400'}>{order.status}</span></p>
                                                <p className="text-gray-400">Price: ₹{order.price}/month</p>
                                            </div>
                                            <div className="bg-green-500/20 border border-green-500 rounded-lg p-3">
                                                <p className="text-green-400 text-sm">Server is Running</p>
                                            </div>
                                        </div>
                                    </div>
                                ))}
                            </div>
                        )}
                    </div>
                </div>
            );
        };
        
        const Admin = ({ user }) => {
            const [users, setUsers] = useState([]);
            const [orders, setOrders] = useState([]);
            const [stats, setStats] = useState({});
            
            useEffect(() => {
                api.get('/admin/users').then(res => setUsers(res.data));
                api.get('/admin/orders').then(res => setOrders(res.data));
                api.get('/admin/stats').then(res => setStats(res.data));
            }, []);
            
            const updateOrderStatus = async (id, status) => {
                await api.put(`/admin/orders/${id}`, { status });
                api.get('/admin/orders').then(res => setOrders(res.data));
            };
            
            const deleteUser = async (id) => {
                if (confirm('Delete user?')) {
                    await api.delete(`/admin/users/${id}`);
                    api.get('/admin/users').then(res => setUsers(res.data));
                }
            };
            
            if (user?.role !== 'admin') return <div className="min-h-screen flex items-center justify-center"><p className="text-red-400">Access denied. Admin only.</p></div>;
            
            return (
                <div className="min-h-screen bg-[#0A0A0F] py-20">
                    <div className="container mx-auto px-4">
                        <h1 className="text-3xl font-bold mb-8">Admin <span className="gradient-text">Panel</span></h1>
                        <div className="grid md:grid-cols-4 gap-4 mb-8">
                            <div className="bg-[#1A1A22] p-6 rounded-2xl text-center"><p className="text-3xl font-bold text-primary">{stats.totalUsers || 0}</p><p className="text-gray-400">Users</p></div>
                            <div className="bg-[#1A1A22] p-6 rounded-2xl text-center"><p className="text-3xl font-bold text-primary">{stats.totalOrders || 0}</p><p className="text-gray-400">Orders</p></div>
                            <div className="bg-[#1A1A22] p-6 rounded-2xl text-center"><p className="text-3xl font-bold text-primary">{stats.activeOrders || 0}</p><p className="text-gray-400">Active</p></div>
                            <div className="bg-[#1A1A22] p-6 rounded-2xl text-center"><p className="text-3xl font-bold text-primary">₹{stats.totalRevenue || 0}</p><p className="text-gray-400">Revenue</p></div>
                        </div>
                        <div className="bg-[#1A1A22] rounded-2xl p-6 mb-8"><h2 className="text-xl font-semibold mb-4">Users</h2>
                            {users.map(u => <div key={u._id} className="flex justify-between items-center border-b border-gray-800 py-3"><div><p className="font-semibold">{u.name}</p><p className="text-sm text-gray-400">{u.email}</p></div><button onClick={() => deleteUser(u._id)} className="text-red-400 hover:text-red-300">Delete</button></div>)}
                        </div>
                        <div className="bg-[#1A1A22] rounded-2xl p-6"><h2 className="text-xl font-semibold mb-4">Orders</h2>
                            {orders.map(o => <div key={o._id} className="flex justify-between items-center border-b border-gray-800 py-3"><div><p className="font-semibold">{o.plan}</p><p className="text-sm text-gray-400">{o.userId?.name} - ₹{o.price}</p></div><select value={o.status} onChange={e => updateOrderStatus(o._id, e.target.value)} className="bg-[#0A0A0F] border border-gray-700 rounded-lg p-1"><option value="pending">Pending</option><option value="active">Active</option><option value="cancelled">Cancelled</option></select></div>)}
                        </div>
                    </div>
                </div>
            );
        };
        
        const HomePage = ({ user, onOrder }) => (
            <>
                <div id="home" className="relative overflow-hidden py-20">
                    <div className="container mx-auto px-4 text-center">
                        <div className="inline-block bg-primary/20 backdrop-blur-sm border border-primary/30 rounded-full px-6 py-2 mb-8">🎉 Use code LENEX10 for 10% off</div>
                        <h1 className="text-5xl md:text-7xl font-bold mb-6">Host your own <span className="gradient-text glow">Minecraft Server</span></h1>
                        <p className="text-gray-400 text-lg md:text-xl max-w-2xl mx-auto mb-10">Lightning-fast performance, unbeatable reliability, and 24/7 support</p>
                        <a href={user ? "#plans" : "#register"} className="btn-gradient px-8 py-4 rounded-lg font-semibold text-lg inline-block">Get Started →</a>
                        <div className="grid md:grid-cols-3 gap-8 mt-16 max-w-3xl mx-auto">
                            <div><i className="fas fa-bolt text-3xl text-primary mb-2 block"></i><h4 className="font-semibold">Instant Setup</h4><p className="text-gray-400 text-sm">Under 60 seconds</p></div>
                            <div><i className="fas fa-shield-alt text-3xl text-primary mb-2 block"></i><h4 className="font-semibold">DDoS Protection</h4><p className="text-gray-400 text-sm">Enterprise-grade</p></div>
                            <div><i className="fas fa-chart-line text-3xl text-primary mb-2 block"></i><h4 className="font-semibold">99.9% Uptime</h4><p className="text-gray-400 text-sm">Guaranteed</p></div>
                        </div>
                    </div>
                </div>
                <Plans onOrder={onOrder} user={user} />
                <Features />
                <Footer />
            </>
        );
        
        // Main App
        const App = () => {
            const [user, setUser] = useState(null);
            const [currentPage, setCurrentPage] = useState('home');
            
            useEffect(() => {
                const token = localStorage.getItem('token');
                const savedUser = localStorage.getItem('user');
                if (token && savedUser) {
                    setUser(JSON.parse(savedUser));
                    api.get('/me').catch(() => { localStorage.clear(); setUser(null); });
                }
            }, []);
            
            const handleLogin = (userData) => { setUser(userData); setCurrentPage('home'); window.location.hash = ''; };
            const handleLogout = () => { localStorage.clear(); setUser(null); setCurrentPage('home'); window.location.hash = ''; };
            const handleOrder = async (plan) => { if (!user) { setCurrentPage('register'); window.location.hash = 'register'; return; } await api.post('/orders', { plan: plan.name, price: plan.price }); alert('Server ordered! Check dashboard.'); };
            
            const hash = window.location.hash.slice(1);
            React.useEffect(() => {
                const handleHash = () => { const h = window.location.hash.slice(1); if (['login', 'register', 'dashboard', 'admin'].includes(h)) setCurrentPage(h); else setCurrentPage('home'); };
                window.addEventListener('hashchange', handleHash);
                handleHash();
                return () => window.removeEventListener('hashchange', handleHash);
            }, []);
            
            const renderPage = () => {
                if (currentPage === 'login') return <Login onLogin={handleLogin} />;
                if (currentPage === 'register') return <Register onLogin={handleLogin} />;
                if (currentPage === 'dashboard') return <Dashboard user={user} />;
                if (currentPage === 'admin') return <Admin user={user} />;
                return <HomePage user={user} onOrder={handleOrder} />;
            };
            
            return (
                <>
                    <Navbar user={user} onLogout={handleLogout} />
                    {renderPage()}
                </>
            );
        };
        
        createRoot(document.getElementById('root')).render(<App />);
    </script>
</body>
</html>
`;

// ========================================
// SERVE HTML
// ========================================

app.get('*', (req, res) => {
  res.send(HTML);
});

// ========================================
// CONNECT MONGODB & START SERVER
// ========================================

mongoose.connect('mongodb://localhost:27017/lenexhost', {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
.then(() => {
  console.log('✅ MongoDB connected');
  app.listen(PORT, () => {
    console.log(`
    ════════════════════════════════════════
    🚀 LENEX HOSTING IS RUNNING!
    📍 http://localhost:${PORT}
    ════════════════════════════════════════
    
    Admin Login (create first):
    1. Register a new account
    2. Then manually set role to 'admin' in MongoDB
    
    Or use test admin:
    Email: admin@lenex.com
    Password: admin123 (create this first)
    `);
  });
})
.catch(err => {
  console.error('❌ MongoDB connection failed:', err.message);
  console.log('\n💡 Please install MongoDB first: https://www.mongodb.com/try/download/community\n');
  process.exit(1);
});