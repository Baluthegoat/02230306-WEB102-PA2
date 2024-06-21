import { Hono } from "hono";
import { cors } from "hono/cors";
import { PrismaClient, Prisma } from "@prisma/client";
import { HTTPException } from "hono/http-exception";
import { decode, sign, verify } from "hono/jwt";
import { jwt } from 'hono/jwt'
import type { JwtVariables } from 'hono/jwt'
import axios from 'axios';

type Variables = JwtVariables

const app = new Hono<{ Variables: Variables }>()

const prisma = new PrismaClient();

app.use("/*", cors());

app.use(
  "/protected/*",
  jwt({
    secret: 'mySecretKey',
  })
);

app.post("/register", async (c) => {
  try {
    const body = await c.req.json();

    const bcryptHash = await Bun.password.hash(body.password, {
      algorithm: "bcrypt",
      cost: 4, // number between 4-31
    });

    const user = await prisma.user.create({
      data: {
        email: body.email,
        username: body.username,
        hashedPassword: bcryptHash,
      },
    });

    return c.json({ message: `${user.email} created successfully}` });
  } catch (e) {
    if (e instanceof Prisma.PrismaClientKnownRequestError) {
      // The .code property can be accessed in a type-safe manner
      if (e.code === "P2002") {
        console.log(  
          "There is a unique constraint violation, a new user cannot be created with this email"
        );
        return c.json({ message: "Email already exists" });
      }
    }
  }
});

app.post("/login", async (c) => {
  try {
    const body = await c.req.json();
    const user = await prisma.user.findUnique({
      where: { email: body.email },
      select: { id: true, hashedPassword: true },
    });

    if (!user) {
      return c.json({ message: "User not found" });
    }

    const match = await Bun.password.verify(
      body.password,
      user.hashedPassword,
      "bcrypt"
    );
    if (match) {
      const payload = {
        sub: user.id,
        exp: Math.floor(Date.now() / 1000) + 60 * 60, // Token expires in 60 minutes
      };
      const secret = "mySecretKey";
      const token = await sign(payload, secret);
      return c.json({ message: "Login successful", token: token });
    } else {
      throw new HTTPException(401, { message: "Invalid credentials" });
    }
  } catch (error) {
    throw new HTTPException(401, { message: "Invalid credentials" });
  }
});

app.post("/protected/pokemon", async (c) => {
  try {
    const payload = c.get("jwtPayload");
    if (!payload) {
      throw new HTTPException(401, { message: "Unauthorized" });
    }
    const body = await c.req.json();
    const pokemon = await prisma.pokemon.create({
      data: {
        name: body.name,
        type: body.type,
        description: body.description,
        userId: payload.sub,
      },
    });
    return c.json({ message: `${pokemon.name} created successfully` });
  } catch (error) {
    throw new HTTPException(401, { message: "Unauthorized" });
  }
});

app.get("/protected/pokemon", async (c) => {
  try {
    const payload = c.get("jwtPayload");
    if (!payload) {
      throw new HTTPException(401, { message: "Unauthorized" });
    }
    const userPokemon = await prisma.pokemon.findMany({
      where: { userId: payload.sub },
    });

    const pokeApiResponse = await axios.get('https://pokeapi.co/api/v2/pokemon?limit=10');
    const pokeApiData = pokeApiResponse.data;

    return c.json({ userPokemon, pokeApiData });
  } catch (error) {
    throw new HTTPException(401, { message: "Unauthorized" });
  }
});

app.put("/protected/pokemon/:id", async (c) =>{
  const payload = c.get("jwtPayload");
  if (!payload) {
    throw new HTTPException(401, { message: "You are idiot :(" });
  }
  const { id } = c.req.param();
  const body = await c.req.json();
  
  const pokemon = await prisma.pokemon.findUnique({ where: {id: Number(id)}});
  if (!pokemon) {
    throw new HTTPException(404, { message: "Not your POKEMON :(" });
  }
  if (payload.sub === pokemon.userId){
    const updatedPokemon = await prisma.pokemon.update({
      where: {id: Number(id)},
      data: {
        name: body.name,
        type: body.type,
        description: body.description,
      },
    });
    return c.json(updatedPokemon);
  } else if (payload.sub !== pokemon.userId){
    throw new HTTPException(401, { message: "Not your POKEMON :(" });
  }
});

app.delete("/protected/pokemon/:id", async (c) =>{
  const payload = c.get("jwtPayload");
  if (!payload) {
    throw new HTTPException(401, { message: "You are idiot :(" });
  }
  const { id } = c.req.param();

  const pokemon = await prisma.pokemon.findUnique({ where: {id: Number(id)}});
  if (!pokemon) {
    throw new HTTPException(404, { message: "Not your POKEMON :(" });
  }
  if (payload.sub === pokemon.userId){
    const deletedPokemon = await prisma.pokemon.delete({ where: {id: Number(id), userId: payload.sub}});
    return c.json(deletedPokemon);
  } else if (payload.sub !== pokemon.userId){
    throw new HTTPException(401, { message: "Not your POKEMON :(" });
  }
});

export default app;