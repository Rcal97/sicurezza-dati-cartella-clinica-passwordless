// Eseguito una sola volta, alla prima creazione del database.
// Crea l'utente del backend con i soli permessi di lettura e scrittura sul proprio database
// (principio del privilegio minimo): l'utente root resta riservato all'amministrazione.
const appDb = process.env.MONGO_APP_DB;

db.getSiblingDB(appDb).createUser({
  user: process.env.MONGO_APP_USER,
  pwd: process.env.MONGO_APP_PASSWORD,
  roles: [{ role: "readWrite", db: appDb }],
});
