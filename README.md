# ChatApp - Real-time Chat Application

A modern, real-time chat application built with Node.js, Express, Socket.IO, and MongoDB. Features both group chat and private messaging with a WhatsApp-inspired interface.

  

## 🌟 Features

### 🔐 Authentication & Security
- **User Registration & Login** with password validation
- **JWT-based Authentication** with secure cookies
- **Password Reset** via OTP email verification
- **Input Validation** and sanitization
- **Secure File Uploads** with type restrictions

### 💬 Real-time Messaging
- **Group Chat** - Public chat room for all users
- **Private Messaging** - One-on-one conversations
- **Real-time Message Delivery** without page refresh
- **Message Persistence** - Chat history saved in MongoDB
- **Typing Indicators** - See when someone is typing
- **Online/Offline Status** - Real-time user status updates

### 🎨 Modern UI/UX
- **WhatsApp-inspired Design** with modern gradients
- **Responsive Layout** - Works on desktop and mobile
- **Emoji Picker** - Express yourself with emojis
- **Image Sharing** - Upload and share images
- **Toast Notifications** - Success/error feedback
- **Loading States** - Visual feedback for all actions
- **Image Modal** - Click to view full-size images

### 👤 User Management
- **Custom Status Messages** - Update your status
- **User Profiles** - Avatar with initials
- **Online Indicators** - Pulsing status badges
- **Last Seen** - When users were last active

## 🚀 Quick Start

### Prerequisites
- Node.js (v18 or higher)
- MongoDB (v5.0 or higher)
- npm or yarn

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/yourusername/chatapp.git
   cd chatapp
   ```

2. **Install dependencies**
   ```bash
   npm install
   ```

3. **Set up MongoDB**
   ```bash
   # Make sure MongoDB is running on localhost:27017
   # Or update the connection string in server.js
   ```

4. **Configure Email (Optional - for password reset)**
   ```javascript
   // In server.js, update the nodemailer configuration:
   const transporter = nodemailer.createTransporter({
     service: 'Gmail',
     auth: {
       user: 'your-email@gmail.com',
       pass: 'your-app-password', // Use App Password for Gmail
     },
   });
   ```

5. **Create required directories**
   ```bash
   mkdir uploads
   mkdir views
   ```

6. **Start the application**
   ```bash
   npm start
   # or for development with nodemon:
   npm run dev
   ```

7. **Access the application**
   ```
   http://localhost:3000
   ```

## 📁 Project Structure

```
chatapp/
├── server.js              # Main server file
├── package.json           # Dependencies and scripts
├── views/
│   ├── login.ejs          # Login page
│   ├── register.ejs       # Registration page
│   ├── chat.ejs           # Main chat interface
│   ├── forgot-password.ejs # Password reset request
│   └── reset-password.ejs  # Password reset form
├── uploads/               # Uploaded images
├── styles/               # CSS files (if separate)
└── README.md             # This file
```

## 🛠️ Technologies Used

### Backend
- **Node.js** - Runtime environment
- **Express.js** - Web framework
- **Socket.IO** - Real-time communication
- **MongoDB** - Database
- **Mongoose** - MongoDB ODM
- **JWT** - Authentication tokens
- **bcryptjs** - Password hashing
- **Multer** - File uploads
- **Nodemailer** - Email functionality

### Frontend
- **EJS** - Template engine
- **Bootstrap 5** - CSS framework
- **Font Awesome** - Icons
- **Socket.IO Client** - Real-time client
- **Vanilla JavaScript** - Client-side logic

## 🔧 Configuration

### Environment Variables (Optional)
Create a `.env` file in the root directory:

```env
PORT=3000
MONGODB_URI=mongodb://localhost:27017/ChatApp
JWT_SECRET=your-secret-key-here
EMAIL_USER=your-email@gmail.com
EMAIL_PASS=your-app-password
```

### Update server.js to use environment variables:
```javascript
const PORT = process.env.PORT || 3000;
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/ChatApp';
const JWT_SECRET = process.env.JWT_SECRET || 'secretkey';
```

## 📝 API Endpoints

### Authentication
- `GET /` - Login page
- `GET /login` - Login page
- `POST /login` - User login
- `GET /register` - Registration page
- `POST /register` - User registration
- `POST /logout` - User logout
- `GET /forgot-password` - Password reset request page
- `POST /forgot-password` - Send password reset OTP
- `GET /reset-password` - Password reset form
- `POST /reset-password` - Reset password with OTP

### Chat
- `GET /chat` - Group chat page
- `GET /chat/:recipient` - Private chat page
- `POST /update-status` - Update user status
- `POST /upload-image` - Upload image

### Socket Events
- `chat message` - Send/receive messages
- `typing` - Typing indicator
- `stop typing` - Stop typing indicator
- `emoji reaction` - Emoji reactions
- `status update` - User status updates

## 🎯 Usage

### Getting Started
1. **Register** a new account or **login** with existing credentials
2. **Update your status** to let others know what you're up to
3. **Join the Group Chat** to talk with everyone
4. **Start Private Chats** by clicking on any user

### Features Guide
- **Send Messages**: Type in the input box and press Enter or click send
- **Add Emojis**: Click the smile icon to open emoji picker
- **Share Images**: Click the paperclip icon to upload images
- **View Images**: Click on any shared image to view full size
- **Update Status**: Use the status section in the sidebar
- **Switch Chats**: Click on Group Chat or any user to switch conversations

## 🔒 Security Features

- **Password Requirements**: 8+ characters with uppercase, lowercase, numbers, and special characters
- **JWT Authentication**: Secure token-based authentication
- **Input Validation**: Server-side validation for all inputs
- **File Upload Security**: Restricted file types and size limits
- **XSS Prevention**: Input sanitization and escaping
- **CSRF Protection**: HTTP-only cookies

## 📱 Mobile Responsiveness

The application is fully responsive and works on:
- Desktop computers
- Tablets
- Mobile phones
- Different screen orientations

## 🐛 Troubleshooting

### Common Issues

1. **MongoDB Connection Error**
   ```bash
   # Make sure MongoDB is running
   mongod
   # Or check if MongoDB service is started
   ```

2. **Port Already in Use**
   ```bash
   # Kill process on port 3000
   lsof -ti:3000 | xargs kill -9
   # Or use a different port in server.js
   ```

3. **Images Not Loading**
   ```bash
   # Make sure uploads directory exists
   mkdir uploads
   # Check file permissions
   ```

4. **Email Not Working**
   - Use App Password for Gmail (not regular password)
   - Enable 2-factor authentication first
   - Update email configuration in server.js

