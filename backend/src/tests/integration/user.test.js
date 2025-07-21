import request from 'supertest';
import express from 'express';
import { signup, login, logout, updateProfile, checkAuth } from '../controllers/auth.controller.js';

// Mock dependencies
jest.mock('../lib/utils.js', () => ({
    generateToken: jest.fn()
}));

jest.mock('../lib/cloudinary.js', () => ({
    uploader: {
        upload: jest.fn()
    }
}));

import { generateToken } from '../lib/utils.js';
import cloudinary from '../lib/cloudinary.js';

const app = express();
app.use(express.json());

// Setup routes
app.post('/signup', signup);
app.post('/login', login);
app.post('/logout', logout);
app.put('/update-profile', globalThis.mockAuthenticatedRequest, updateProfile);
app.get('/check-auth', globalThis.mockAuthenticatedRequest, checkAuth);

describe('Auth Controller', () => {
    describe('POST /signup', () => {
        it('should create a new user successfully', async () => {
            const userData = {
                fullName: 'John Doe',
                email: 'john@example.com',
                password: 'password123'
            };

            generateToken.mockImplementation(() => { }); // Mock token generation

            const response = await request(app)
                .post('/signup')
                .send(userData);

            expect(response.status).toBe(201);
            expect(response.body).toHaveProperty('_id');
            expect(response.body.fullName).toBe(userData.fullName);
            expect(response.body.email).toBe(userData.email);
            expect(response.body).not.toHaveProperty('password'); // Password should not be returned
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
        });

        it('should return 400 if password is too short', async () => {
            const response = await request(app)
                .post('/signup')
                .send({
                    fullName: 'John Doe',
                    email: 'john@example.com',
                    password: '123' // Too short
                });

            expect(response.status).toBe(400);
            expect(response.body.message).toBe('Password must be at least 6 characters');
        });

        it('should return 400 if email already exists', async () => {
            const response = await request(app)
                .post('/signup')
                .send({
                    fullName: 'Test User',
                    email: 'test@example.com', // This email already exists from setup
                    password: 'password123'
                });

            expect(response.status).toBe(400);
            expect(response.body.message).toBe('Email already exists');
        });
    });

    describe('POST /login', () => {
        it('should login user with correct credentials', async () => {
            generateToken.mockImplementation(() => { }); // Mock token generation

            const response = await request(app)
                .post('/login')
                .send({
                    email: 'test@example.com',
                    password: 'password123'
                });

            expect(response.status).toBe(200);
            expect(response.body).toHaveProperty('_id');
            expect(response.body.email).toBe('test@example.com');
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
        });
    });

    describe('POST /logout', () => {
        it('should logout user successfully', async () => {
            const response = await request(app)
                .post('/logout');

            expect(response.status).toBe(200);
            expect(response.body.message).toBe('Logged out successfully');
        });
    });

    describe('PUT /update-profile', () => {
        beforeEach(() => {
            // Reset mocks before each test
            cloudinary.uploader.upload.mockReset();
        });

        it('should update profile picture successfully', async () => {
            const mockProfilePic = 'data:image/jpeg;base64,mockImageData';
            const mockUploadResponse = {
                secure_url: 'https://cloudinary.com/mock-image.jpg'
            };

            cloudinary.uploader.upload.mockResolvedValue(mockUploadResponse);

            const response = await request(app)
                .put('/update-profile')
                .send({ profilePic: mockProfilePic });

            expect(response.status).toBe(200);
            expect(response.body.profilePic).toBe(mockUploadResponse.secure_url);
            expect(cloudinary.uploader.upload).toHaveBeenCalledWith(mockProfilePic);
        });

        it('should return 400 if profile pic is missing', async () => {
            const response = await request(app)
                .put('/update-profile')
                .send({});

            expect(response.status).toBe(400);
            expect(response.body.message).toBe('Profile pic is required');
        });

        it('should handle cloudinary upload error', async () => {
            cloudinary.uploader.upload.mockRejectedValue(new Error('Upload failed'));

            const response = await request(app)
                .put('/update-profile')
                .send({ profilePic: 'data:image/jpeg;base64,mockImageData' });

            expect(response.status).toBe(500);
            expect(response.body.message).toBe('Internal server error');
        });
    });

    describe('GET /check-auth', () => {
        it('should return authenticated user data', async () => {
            const response = await request(app)
                .get('/check-auth');

            expect(response.status).toBe(200);
            expect(response.body._id).toBe(globalThis.mockUser._id.toString());
            expect(response.body.email).toBe(globalThis.mockUser.email);
        });
    });
});