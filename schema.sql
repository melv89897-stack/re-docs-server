create table if not exists users (
  id uuid default gen_random_uuid() primary key,
  name text not null,
  email text unique not null,
  password_hash text not null,
  subscribed boolean default false,
  unlocked_docs text[] default '{}',
  created_at timestamp with time zone default now()
);
