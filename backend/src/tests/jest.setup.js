import mongoose from 'mongoose';
import User from '../models/user.model.js';
import Message from '../models/message.model.js';
import bcrypt from 'bcryptjs';

let testUser;

beforeAll(async () => {
    // Connect to test database
    await mongoose.connect("mongodb://localhost:27017/test");

    // Clean up existing data
    await User.deleteMany({});
    await Message.deleteMany({});

    // Hash the password like in your signup controller
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash('password123', salt);

    // Create test user with hashed password
    testUser = await User.create({
        fullName: 'Test User',
        email: 'test@example.com',
        password: hashedPassword, // Use hashed password
    });

    // Set up global test data
    globalThis.mockUser = {
        _id: testUser._id,
        fullName: testUser.fullName,
        email: testUser.email,
        profilePic: testUser.profilePic || null
    };

    globalThis.userId = testUser._id;

    // Mock req.user for authenticated routes
    globalThis.mockAuthenticatedRequest = (req, res, next) => {
        req.user = globalThis.mockUser;
        next();
    };
});

afterAll(async () => {
    // Clean up test data
    await Message.deleteMany({});
    await User.deleteMany({});
    await mongoose.disconnect();
});

beforeEach(async () => {
    // Clean messages before each test to ensure isolation
    await Message.deleteMany({});
});

// Helper function to create additional test users
globalThis.createTestUser = async (userData = {}) => {
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(userData.password || 'password123', salt);

    const defaultData = {
        fullName: 'Additional Test User',
        email: 'test2@example.com',
        password: hashedPassword
    };

    return await User.create({ ...defaultData, ...userData, password: hashedPassword });
};

// Helper function to create test messages
globalThis.createTestMessage = async (messageData = {}) => {
    const defaultData = {
        senderId: globalThis.userId,
        receiverId: new mongoose.Types.ObjectId(),
        text: 'Test message',
        image: null
    };

    return await Message.create({ ...defaultData, ...messageData });
};