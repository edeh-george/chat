import request from 'supertest';
import app from '../../index.js';
import User from '../../models/user.model.js';
import Message from '../../models/message.model.js';
import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';

let testUser;
let testToken;

beforeAll(async () => {
    // Connect to test database
    const testDbUrl = process.env.TEST_DB_URL || "mongodb://localhost:27017/test_messages";
    await mongoose.connect(testDbUrl);

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
        password: hashedPassword,
        username: 'testuser1'
    });

    // Generate a real JWT token for authentication
    testToken = jwt.sign(
        { userId: testUser._id },
        process.env.JWT_SECRET || 'test-secret',
        { expiresIn: '1h' }
    );

    // Set up global test data
    globalThis.mockUser = {
        _id: testUser._id,
        fullName: testUser.fullName,
        email: testUser.email,
        username: testUser.username,
        profilePic: testUser.profilePic || null
    };

    globalThis.userId = testUser._id;
    globalThis.token = testToken;
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
        email: `test${Date.now()}@example.com`,
        username: `testuser${Date.now()}`,
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

describe('Message Controller', () => {
    let testUser2;

    beforeEach(async () => {
        // Create a second user for testing conversations
        testUser2 = await globalThis.createTestUser({
            username: 'testuser2',
            email: 'test2@example.com',
            fullName: 'Test User 2'
        });
    });

    afterEach(async () => {
        // Clean up additional test users (keep main test user)
        await User.deleteMany({ _id: { $ne: globalThis.userId } });
    });

    describe('GET /api/users - getUsersForSidebar', () => {
        it('should get all users except logged in user', async () => {
            // Create additional users
            const user3 = await globalThis.createTestUser({
                username: 'testuser3',
                email: 'test3@example.com',
                fullName: 'Test User 3'
            });

            const response = await request(app)
                .get('/api/users')
                .set('Authorization', `Bearer ${globalThis.token}`)
                .expect(200);

            expect(response.body).toHaveLength(2); // testUser2 and user3
            expect(response.body.some(user => user._id.toString() === testUser2._id.toString())).toBe(true);
            expect(response.body.some(user => user._id.toString() === user3._id.toString())).toBe(true);
            expect(response.body.some(user => user._id.toString() === globalThis.userId.toString())).toBe(false);

            // Check that passwords are not included
            response.body.forEach(user => {
                expect(user.password).toBeUndefined();
            });
        });

        it('should return empty array when no other users exist', async () => {
            // Remove testUser2
            await User.findByIdAndDelete(testUser2._id);

            const response = await request(app)
                .get('/api/users')
                .set('Authorization', `Bearer ${globalThis.token}`)
                .expect(200);

            expect(response.body).toHaveLength(0);
        });

        it('should handle unauthorized requests', async () => {
            const response = await request(app)
                .get('/api/users')
                .expect(401);

            expect(response.body).toHaveProperty('error');
        });
    });

    describe('GET /api/messages/:id - getMessages', () => {
        beforeEach(async () => {
            // Create test messages between users
            await globalThis.createTestMessage({
                senderId: globalThis.userId,
                receiverId: testUser2._id,
                text: 'Hello from user 1'
            });

            await globalThis.createTestMessage({
                senderId: testUser2._id,
                receiverId: globalThis.userId,
                text: 'Hello from user 2'
            });
        });

        it('should get messages between two users', async () => {
            const response = await request(app)
                .get(`/api/messages/${testUser2._id}`)
                .set('Authorization', `Bearer ${globalThis.token}`)
                .expect(200);

            expect(response.body).toHaveLength(2);

            const messages = response.body;
            expect(messages.some(msg => msg.text === 'Hello from user 1')).toBe(true);
            expect(messages.some(msg => msg.text === 'Hello from user 2')).toBe(true);

            // Verify message structure
            messages.forEach(msg => {
                expect(msg).toHaveProperty('_id');
                expect(msg).toHaveProperty('senderId');
                expect(msg).toHaveProperty('receiverId');
                expect(msg).toHaveProperty('text');
                expect(msg).toHaveProperty('createdAt');
            });
        });

        it('should return empty array when no messages exist', async () => {
            // Create a third user with no messages
            const user3 = await globalThis.createTestUser({
                username: 'testuser3',
                email: 'test3@example.com'
            });

            const response = await request(app)
                .get(`/api/messages/${user3._id}`)
                .set('Authorization', `Bearer ${globalThis.token}`)
                .expect(200);

            expect(response.body).toHaveLength(0);
        });

        it('should handle invalid user ID', async () => {
            const invalidId = 'invalid-id';

            const response = await request(app)
                .get(`/api/messages/${invalidId}`)
                .set('Authorization', `Bearer ${globalThis.token}`)
                .expect(500);

            expect(response.body).toHaveProperty('error');
        });
    });

    describe('POST /api/messages/:id - sendMessage', () => {
        it('should send text message successfully', async () => {
            const messageData = { text: 'Hello World' };

            const response = await request(app)
                .post(`/api/messages/${testUser2._id}`)
                .set('Authorization', `Bearer ${globalThis.token}`)
                .send(messageData)
                .expect(201);

            expect(response.body).toHaveProperty('_id');
            expect(response.body.senderId.toString()).toBe(globalThis.userId.toString());
            expect(response.body.receiverId.toString()).toBe(testUser2._id.toString());
            expect(response.body.text).toBe('Hello World');
            expect(response.body.image).toBeFalsy();

            // Verify message was saved to database
            const savedMessage = await Message.findById(response.body._id);
            expect(savedMessage).toBeTruthy();
            expect(savedMessage.text).toBe('Hello World');
        });

        it('should send message with image successfully', async () => {
            // Use a small, valid base64 image for testing
            const base64Image = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==';
            const messageData = {
                text: 'Check this image!',
                image: base64Image
            };

            const response = await request(app)
                .post(`/api/messages/${testUser2._id}`)
                .set('Authorization', `Bearer ${globalThis.token}`)
                .send(messageData)
                .expect(201);

            expect(response.body.text).toBe('Check this image!');
            expect(response.body.image).toBeTruthy();
            expect(response.body.image).toMatch(/^https?:\/\//); // Should be a valid URL

            // Verify message was saved with image URL
            const savedMessage = await Message.findById(response.body._id);
            expect(savedMessage.image).toBeTruthy();
        });

        it('should handle empty message text', async () => {
            const messageData = { text: '' };

            const response = await request(app)
                .post(`/api/messages/${testUser2._id}`)
                .set('Authorization', `Bearer ${globalThis.token}`)
                .send(messageData)
                .expect(201);

            expect(response.body.text).toBe('');

            // Verify empty message was saved
            const savedMessage = await Message.findById(response.body._id);
            expect(savedMessage.text).toBe('');
        });

        it('should handle unauthorized requests', async () => {
            const messageData = { text: 'Unauthorized message' };

            const response = await request(app)
                .post(`/api/messages/${testUser2._id}`)
                .send(messageData)
                .expect(401);

            expect(response.body).toHaveProperty('error');
        });

        it('should handle invalid receiver ID', async () => {
            const messageData = { text: 'Invalid receiver' };
            const invalidId = 'invalid-id';

            const response = await request(app)
                .post(`/api/messages/${invalidId}`)
                .set('Authorization', `Bearer ${globalThis.token}`)
                .send(messageData)
                .expect(500);

            expect(response.body).toHaveProperty('error');
        });

        it('should handle message with both text and image', async () => {
            const messageData = {
                text: 'Check this out!',
                image: 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=='
            };

            const response = await request(app)
                .post(`/api/messages/${testUser2._id}`)
                .set('Authorization', `Bearer ${globalThis.token}`)
                .send(messageData)
                .expect(201);

            expect(response.body.text).toBe('Check this out!');
            expect(response.body.image).toBeTruthy();

            // Verify both text and image were saved
            const savedMessage = await Message.findById(response.body._id);
            expect(savedMessage.text).toBe('Check this out!');
            expect(savedMessage.image).toBeTruthy();
        });

        it('should handle message with only image (no text)', async () => {
            const messageData = {
                image: 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=='
            };

            const response = await request(app)
                .post(`/api/messages/${testUser2._id}`)
                .set('Authorization', `Bearer ${globalThis.token}`)
                .send(messageData)
                .expect(201);

            expect(response.body.image).toBeTruthy();
            expect(response.body.text || '').toBe('');
        });
    });

    describe('Database Integration', () => {
        it('should maintain message order by creation time', async () => {
            // Create messages with slight delays to ensure different timestamps
            const message1 = await globalThis.createTestMessage({
                senderId: globalThis.userId,
                receiverId: testUser2._id,
                text: 'First message'
            });

            // Small delay
            await new Promise(resolve => setTimeout(resolve, 10));

            const message2 = await globalThis.createTestMessage({
                senderId: testUser2._id,
                receiverId: globalThis.userId,
                text: 'Second message'
            });

            const response = await request(app)
                .get(`/api/messages/${testUser2._id}`)
                .set('Authorization', `Bearer ${globalThis.token}`)
                .expect(200);

            expect(response.body).toHaveLength(2);

            // Messages should be ordered by creation time
            const firstMessage = response.body[0];
            const secondMessage = response.body[1];

            expect(new Date(firstMessage.createdAt).getTime()).toBeLessThan(
                new Date(secondMessage.createdAt).getTime()
            );
        });

        it('should handle concurrent message sending', async () => {
            const messagePromises = [];

            for (let i = 0; i < 5; i++) {
                messagePromises.push(
                    request(app)
                        .post(`/api/messages/${testUser2._id}`)
                        .set('Authorization', `Bearer ${globalThis.token}`)
                        .send({ text: `Concurrent message ${i}` })
                );
            }

            const responses = await Promise.all(messagePromises);

            responses.forEach(response => {
                expect(response.status).toBe(201);
            });

            // Verify all messages were saved
            const messages = await Message.find({}).sort({ createdAt: 1 });
            expect(messages).toHaveLength(5);
        });

        it('should properly handle message conversations between specific users', async () => {
            // Create a third user
            const user3 = await globalThis.createTestUser({
                username: 'testuser3',
                email: 'test3@example.com',
                fullName: 'Test User 3'
            });

            // Create messages between different user pairs
            await globalThis.createTestMessage({
                senderId: globalThis.userId,
                receiverId: testUser2._id,
                text: 'Message to user2'
            });

            await globalThis.createTestMessage({
                senderId: globalThis.userId,
                receiverId: user3._id,
                text: 'Message to user3'
            });

            await globalThis.createTestMessage({
                senderId: testUser2._id,
                receiverId: user3._id,
                text: 'Message between user2 and user3'
            });

            // Get messages between testUser and testUser2
            const response = await request(app)
                .get(`/api/messages/${testUser2._id}`)
                .set('Authorization', `Bearer ${globalThis.token}`)
                .expect(200);

            // Should only get messages between testUser and testUser2
            expect(response.body).toHaveLength(1);
            expect(response.body[0].text).toBe('Message to user2');

            // Verify messages don't leak between different conversations
            const response2 = await request(app)
                .get(`/api/messages/${user3._id}`)
                .set('Authorization', `Bearer ${globalThis.token}`)
                .expect(200);

            expect(response2.body).toHaveLength(1);
            expect(response2.body[0].text).toBe('Message to user3');
        });
    });
});