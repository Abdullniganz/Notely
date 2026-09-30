# Notely 2.0

A full-stack notes, friends, real-time chat, and voice/video calling app.

## Included

- Account registration and login
- Secure password hashing with bcrypt
- JWT authentication
- SQLite database
- Search people by username/display name
- Send, accept, and decline friend requests
- Server-side friendship checks
- Block/unblock
- Notes create/edit/delete/restore
- Favorites
- Share notes with accepted friends
- Real-time Socket.IO messages and typing indicators
- Browser WebRTC voice/video calls
- STUN signaling and ICE candidate exchange
- Dark/light theme
- Responsive UI

## Run

Requirements: Node.js 18+

```bash
npm install
```

Copy `.env.example` to `.env` and set a strong `JWT_SECRET`.

```bash
npm start
```

Open:

http://localhost:3000

The SQLite database is created automatically in `data/notely.sqlite`.

## Calling

Calls use browser WebRTC. The app includes peer connection setup, microphone/camera access, SDP offer/answer exchange, ICE candidate signaling, and a public STUN server.

For reliable production calls across restrictive networks, configure a TURN server and use HTTPS. Browsers generally require a secure context for camera/microphone access when the app is not running on localhost.

## Production checklist

- Use a strong random JWT secret
- HTTPS
- TURN server
- Rate limiting
- Email verification and password reset
- Account deletion
- More detailed validation
- Backups/monitoring
- Secure deployment environment variables
- Privacy/moderation/reporting tools
