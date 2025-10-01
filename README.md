# budgeteer-api (Node/Express + Prisma + Firebase Admin)

## Quick start
1) Start Postgres (Docker):
```
docker run --name pg -e POSTGRES_PASSWORD=postgres -p 5432:5432 -d postgres:16
```
2) Copy env:
```
cp .env.example .env
# fill FIREBASE_* values from your service account
```
3) Install & migrate:
```
npm i
npm run prisma:migrate -- -n init
```
4) Run:
```
npm run dev
```
Hit http://localhost:4000/health

The app expects a Firebase ID token in `Authorization: Bearer <token>` for protected routes.
