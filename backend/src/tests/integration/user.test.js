import request from 'supertest';
import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import app from '../../index.js';
import { protectRoute } from '../../middleware/auth.middleware.js';
import { signup, login, logout, updateProfile, checkAuth } from '../../controllers/auth.controller.js';
import User from '../../models/user.model.js';

let testUser;

beforeAll(async () => {
    // Close any existing connection first
    if (mongoose.connection.readyState !== 0) {
        await mongoose.disconnect();
    }

    // Connect to test database
    await mongoose.connect("mongodb://localhost:27017/test", {
        useNewUrlParser: true,
        useUnifiedTopology: true,
    });

    // Clean up existing data
    await User.deleteMany({});

    // Hash the password like in your signup controller
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash('password123', salt);

    // Create test user with hashed password
    testUser = await User.create({
        fullName: 'Test User',
        email: 'test@example.com',
        password: hashedPassword,
        // Add username if your schema requires it
        username: 'testuser'
    });

    // Set up global test data
    globalThis.mockUser = {
        _id: testUser._id,
        fullName: testUser.fullName,
        email: testUser.email,
        profilePic: testUser.profilePic || null
    };

    globalThis.userId = testUser._id;
});

afterAll(async () => {
    // Clean up test data
    await User.deleteMany({});
    await mongoose.disconnect();
});

beforeEach(async () => {
    // Recreate the test user before each test instead of deleting all users
    await User.deleteMany({});

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash('password123', salt);

    testUser = await User.create({
        fullName: 'Test User',
        email: 'test@example.com',
        password: hashedPassword,
        // Add username if your schema requires it
        username: 'testuser'
    });

    // Update global references
    globalThis.mockUser = {
        _id: testUser._id,
        fullName: testUser.fullName,
        email: testUser.email,
        profilePic: testUser.profilePic || null
    };
    globalThis.userId = testUser._id;
});

// Helper function to create additional test users
globalThis.createTestUser = async (userData = {}) => {
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(userData.password || 'password123', salt);

    const defaultData = {
        fullName: 'Additional Test User',
        email: 'test2@example.com',
        password: hashedPassword,
        username: userData.username || `testuser${Date.now()}` // Unique username
    };

    return await User.create({ ...defaultData, ...userData, password: hashedPassword });
};

// Setup routes
app.post('/signup', signup);
app.post('/login', login);
app.post('/logout', logout);
app.put('/update-profile', protectRoute, updateProfile);
app.get('/check-auth', protectRoute, checkAuth);

describe('Auth Controller Integration Tests', () => {
    describe('POST /signup', () => {
        it('should create a new user successfully', async () => {
            const userData = {
                fullName: 'John Doe',
                email: 'john@example.com',
                password: 'password123',
                username: 'johndoe' // Add username if required
            };

            const response = await request(app)
                .post('/signup')
                .send(userData);

            expect(response.status).toBe(201);
            expect(response.body).toHaveProperty('_id');
            expect(response.body.fullName).toBe(userData.fullName);
            expect(response.body.email).toBe(userData.email);
            expect(response.body).not.toHaveProperty('password'); // Password should not be returned

            // Verify JWT token was set in cookie
            const cookies = response.headers['set-cookie'];
            expect(cookies).toBeDefined();
            const jwtCookie = cookies.find(cookie => cookie.startsWith('jwt='));
            expect(jwtCookie).toBeDefined();

            // Verify user was actually created in database
            const createdUser = await User.findOne({ email: userData.email });
            expect(createdUser).toBeTruthy();
            expect(createdUser.fullName).toBe(userData.fullName);
        });

        it('should return 400 if fields are missing', async () => {
            const response = await request(app)
                .post('/signup')
                .send({
                    fullName: 'John Doe',
                    email: 'john@example.com'
                    // password missing
                });

            expect(response.status).toBe(400);
            expect(response.body.message).toBe('All fields are required');

            // Verify no user was created
            const user = await User.findOne({ email: 'john@example.com' });
            expect(user).toBeFalsy();
        });

        it('should return 400 if password is too short', async () => {
            const response = await request(app)
                .post('/signup')
                .send({
                    fullName: 'John Doe',
                    email: 'john@example.com',
                    password: '123', // Too short
                    username: 'johndoe123'
                });

            expect(response.status).toBe(400);
            expect(response.body.message).toBe('Password must be at least 6 characters');

            // Verify no user was created
            const user = await User.findOne({ email: 'john@example.com' });
            expect(user).toBeFalsy();
        });

        it('should return 400 if email already exists', async () => {
            const response = await request(app)
                .post('/signup')
                .send({
                    fullName: 'Test User Duplicate',
                    email: 'test@example.com', // This email already exists from setup
                    password: 'password123',
                    username: 'testuserdupe'
                });

            expect(response.status).toBe(400);
            expect(response.body.message).toBe('Email already exists');

            // Verify original user data wasn't modified
            const user = await User.findOne({ email: 'test@example.com' });
            expect(user.fullName).toBe('Test User'); // Original name
        });
    });

    describe('POST /login', () => {
        it('should login user with correct credentials', async () => {
            const response = await request(app)
                .post('/login')
                .send({
                    email: 'test@example.com',
                    password: 'password123'
                });

            expect(response.status).toBe(200);
            expect(response.body).toHaveProperty('_id');
            expect(response.body.email).toBe('test@example.com');
            expect(response.body.fullName).toBe('Test User');

            // Verify JWT token was set in cookie
            const cookies = response.headers['set-cookie'];
            expect(cookies).toBeDefined();
            const jwtCookie = cookies.find(cookie => cookie.startsWith('jwt='));
            expect(jwtCookie).toBeDefined();

            // Verify token is valid
            const token = jwtCookie.split('=')[1].split(';')[0];
            const decoded = jwt.verify(token, process.env.JWT_SECRET || 'test-secret');
            expect(decoded.userId).toBe(testUser._id.toString());
        });

        it('should return 400 for non-existent email', async () => {
            const response = await request(app)
                .post('/login')
                .send({
                    email: 'nonexistent@example.com',
                    password: 'password123'
                });

            expect(response.status).toBe(400);
            expect(response.body.message).toBe('Invalid credentials');

            // Verify no token was set
            const cookies = response.headers['set-cookie'];
            if (cookies) {
                const jwtCookie = cookies.find(cookie => cookie.startsWith('jwt='));
                expect(jwtCookie).toBeFalsy();
            }
        });

        it('should return 400 for incorrect password', async () => {
            const response = await request(app)
                .post('/login')
                .send({
                    email: 'test@example.com',
                    password: 'wrongpassword'
                });

            expect(response.status).toBe(400);
            expect(response.body.message).toBe('Invalid credentials');

            // Verify no token was set
            const cookies = response.headers['set-cookie'];
            if (cookies) {
                const jwtCookie = cookies.find(cookie => cookie.startsWith('jwt='));
                expect(jwtCookie).toBeFalsy();
            }
        });
    });

    describe('POST /logout', () => {
        it('should logout user successfully', async () => {
            const response = await request(app)
                .post('/logout');

            expect(response.status).toBe(200);
            expect(response.body.message).toBe('Logged out successfully');

            // Verify JWT cookie was cleared
            const cookies = response.headers['set-cookie'];
            expect(cookies).toBeDefined();
            const jwtCookie = cookies.find(cookie => cookie.startsWith('jwt='));
            expect(jwtCookie).toContain('jwt=;'); // Empty cookie value
        });
    });

    describe('PUT /update-profile', () => {
        let loginCookie;

        beforeEach(async () => {
            // Login before each test to get valid session
            const loginResponse = await request(app)
                .post('/login')
                .send({
                    email: 'test@example.com',
                    password: 'password123'
                });

            const cookies = loginResponse.headers['set-cookie'];
            loginCookie = cookies.find(cookie => cookie.startsWith('jwt='));
        });

        it('should update profile picture successfully with valid base64 image', async () => {
            const mockProfilePic = 'data:image/jpeg;base64,/9j/4AAQSkZJRgABAQAAAQABAAD/2wBDAAYEBQYFBAYGBQYHBwYIChAKCgkJChQODwwQFxQYGBcUFhYaHSUfGhsjHBYWICwgIyYnKSopGR8tMC0oMCUoKSj/2wBDAQcHBwoIChMKChMoGhYaKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCj/wAARCAABAAEDASIAAhEBAxEB/8QAFQABAQAAAAAAAAAAAAAAAAAAAAv/xAAUEAEAAAAAAAAAAAAAAAAAAAAA/8QAFQEBAQAAAAAAAAAAAAAAAAAAAAX/xAAUEQEAAAAAAAAAAAAAAAAAAAAA/9oADAMBAAIRAxEAPwCdABmX/9k=';

            const response = await request(app)
                .put('/update-profile')
                .set('Cookie', loginCookie)
                .send({ profilePic: mockProfilePic });

            expect(response.status).toBe(200);
            expect(response.body).toHaveProperty('profilePic');
            expect(response.body.profilePic).toMatch(/^https:\/\//); // Should be a valid URL

            // Verify user was updated in database
            const updatedUser = await User.findById(testUser._id);
            expect(updatedUser.profilePic).toBe(response.body.profilePic);
        });

        it('should return 400 if profile pic is missing', async () => {
            const response = await request(app)
                .put('/update-profile')
                .set('Cookie', loginCookie)
                .send({});

            expect(response.status).toBe(400);
            expect(response.body.message).toBe('Profile pic is required');

            // Verify user wasn't modified
            const user = await User.findById(testUser._id);
            expect(user.profilePic).toBe(testUser.profilePic);
        });

        it('should return 400 for invalid base64 image format', async () => {
            const invalidProfilePic = 'invalid-image-data';

            const response = await request(app)
                .put('/update-profile')
                .set('Cookie', loginCookie)
                .send({ profilePic: invalidProfilePic });

            // This depends on your validation - might be 400 or 500
            expect([400, 500]).toContain(response.status);

            // Verify user wasn't modified
            const user = await User.findById(testUser._id);
            expect(user.profilePic).toBe(testUser.profilePic);
        });

        it('should handle empty profile pic string', async () => {
            const response = await request(app)
                .put('/update-profile')
                .set('Cookie', loginCookie)
                .send({ profilePic: '' });

            expect(response.status).toBe(400);
            expect(response.body.message).toBe('Profile pic is required');
        });
    });

    describe('GET /check-auth', () => {
        let loginCookie;

        beforeEach(async () => {
            // Login before test to get valid session
            const loginResponse = await request(app)
                .post('/login')
                .send({
                    email: 'test@example.com',
                    password: 'password123'
                });

            const cookies = loginResponse.headers['set-cookie'];
            loginCookie = cookies.find(cookie => cookie.startsWith('jwt='));
        });

        it('should return authenticated user data', async () => {
            const response = await request(app)
                .get('/check-auth')
                .set('Cookie', loginCookie);

            expect(response.status).toBe(200);
            expect(response.body._id).toBe(testUser._id.toString());
            expect(response.body.email).toBe(testUser.email);
            expect(response.body.fullName).toBe(testUser.fullName);
            expect(response.body).not.toHaveProperty('password');

            // Verify the returned data matches database
            const dbUser = await User.findById(testUser._id);
            expect(response.body.email).toBe(dbUser.email);
            expect(response.body.fullName).toBe(dbUser.fullName);
        });
    });

    describe('Edge Cases and Integration Scenarios', () => {
        it('should handle concurrent signups with same email', async () => {
            const userData = {
                fullName: 'Concurrent User',
                email: 'concurrent@example.com',
                password: 'password123',
                username: 'concurrentuser'
            };

            // Try to create two users with same email simultaneously
            const [response1, response2] = await Promise.allSettled([
                request(app).post('/signup').send(userData),
                request(app).post('/signup').send({ ...userData, username: 'concurrentuser2' })
            ]);

            // One should succeed, one should fail
            const responses = [response1.value, response2.value].filter(Boolean);
            const successCount = responses.filter(r => r.status === 201).length;
            const errorCount = responses.filter(r => r.status === 400).length;

            expect(successCount).toBe(1);
            expect(errorCount).toBe(1);

            // Verify only one user was created
            const users = await User.find({ email: 'concurrent@example.com' });
            expect(users).toHaveLength(1);
        });

        it('should maintain session after profile update', async () => {
            // First login to get a session
            const loginResponse = await request(app)
                .post('/login')
                .send({
                    email: 'test@example.com',
                    password: 'password123'
                });

            expect(loginResponse.status).toBe(200);

            // Extract cookie
            const cookies = loginResponse.headers['set-cookie'];
            const jwtCookie = cookies.find(cookie => cookie.startsWith('jwt='));

            // Update profile using the session
            const updateResponse = await request(app)
                .put('/update-profile')
                .set('Cookie', jwtCookie)
                .send({ profilePic: 'data:image/jpeg;base64,/9j/4AAQSkZJRgABAQAAAQABAAD//2Q==' });

            expect(updateResponse.status).toBe(200);

            // Verify session is still valid by checking auth
            const authResponse = await request(app)
                .get('/check-auth')
                .set('Cookie', jwtCookie);

            expect(authResponse.status).toBe(200);
        });
    });
});