const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const path = require('path');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 3002;
const SECRET = process.env.JWT_SECRET || 'edgecars_secret_2024';
const db = new Database(path.join(__dirname, 'cars.db'));

// ── INIT DB
db.exec(`
  CREATE TABLE IF NOT EXISTS vehicules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    lot_number TEXT, vin TEXT,
    marque TEXT NOT NULL, modele TEXT NOT NULL,
    annee INTEGER, couleur TEXT,
    carburant TEXT DEFAULT 'essence',
    transmission TEXT DEFAULT 'automatique',
    kilometrage INTEGER DEFAULT 0,
    etat TEXT DEFAULT 'en_transit',
    mode TEXT DEFAULT 'revente',
    notes TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS couts_achat (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    vehicule_id INTEGER UNIQUE,
    prix_bid INTEGER DEFAULT 0,
    frais_copart INTEGER DEFAULT 0,
    towing INTEGER DEFAULT 0,
    autres_usa INTEGER DEFAULT 0,
    FOREIGN KEY (vehicule_id) REFERENCES vehicules(id) ON DELETE CASCADE
  );
  CREATE TABLE IF NOT EXISTS couts_transport (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    vehicule_id INTEGER UNIQUE,
    shipping INTEGER DEFAULT 0,
    compagnie TEXT, date_depart DATE,
    date_arrivee_estimee DATE, date_arrivee_reelle DATE,
    numero_bl TEXT,
    FOREIGN KEY (vehicule_id) REFERENCES vehicules(id) ON DELETE CASCADE
  );
  CREATE TABLE IF NOT EXISTS couts_port (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    vehicule_id INTEGER UNIQUE,
    dedouanement INTEGER DEFAULT 0,
    debarquement INTEGER DEFAULT 0,
    magasinage INTEGER DEFAULT 0,
    livraison_port INTEGER DEFAULT 0,
    autres_port INTEGER DEFAULT 0,
    FOREIGN KEY (vehicule_id) REFERENCES vehicules(id) ON DELETE CASCADE
  );
  CREATE TABLE IF NOT EXISTS reparations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    vehicule_id INTEGER,
    type TEXT NOT NULL, description TEXT,
    montant INTEGER NOT NULL, fournisseur TEXT,
    date DATE DEFAULT CURRENT_DATE,
    FOREIGN KEY (vehicule_id) REFERENCES vehicules(id) ON DELETE CASCADE
  );
  CREATE TABLE IF NOT EXISTS reventes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    vehicule_id INTEGER UNIQUE,
    prix_vente INTEGER, acheteur_nom TEXT, acheteur_tel TEXT,
    date_vente DATE, acompte INTEGER DEFAULT 0,
    statut TEXT DEFAULT 'en_cours', notes TEXT,
    FOREIGN KEY (vehicule_id) REFERENCES vehicules(id) ON DELETE CASCADE
  );
  CREATE TABLE IF NOT EXISTS chauffeurs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    nom TEXT NOT NULL, telephone TEXT, email TEXT, permis TEXT,
    vehicule_id INTEGER, montant_journalier INTEGER DEFAULT 0,
    date_debut DATE, statut TEXT DEFAULT 'actif', notes TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (vehicule_id) REFERENCES vehicules(id)
  );
  CREATE TABLE IF NOT EXISTS versements (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    chauffeur_id INTEGER, vehicule_id INTEGER,
    date DATE NOT NULL,
    montant_attendu INTEGER DEFAULT 0, montant_verse INTEGER DEFAULT 0,
    kilometrage INTEGER DEFAULT 0, statut TEXT DEFAULT 'en_attente', notes TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (chauffeur_id) REFERENCES chauffeurs(id)
  );
  CREATE TABLE IF NOT EXISTS admins (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    nom TEXT, email TEXT UNIQUE, password TEXT, role TEXT DEFAULT 'admin'
  );
`);

// Admin par défaut
if (!db.prepare('SELECT COUNT(*) as n FROM admins').get().n) {
  db.prepare('INSERT INTO admins (nom,email,password,role) VALUES (?,?,?,?)').run('Admin EDGE', 'admin@edgeprod.sn', bcrypt.hashSync('edgecars2024',10), 'admin');
}

// ── MIDDLEWARE
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({ origin: '*' }));
app.use(morgan('combined'));
app.use(express.json());
app.use(express.static(__dirname));

const auth = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Non autorisé' });
  try { req.admin = jwt.verify(token, SECRET); next(); }
  catch { res.status(401).json({ error: 'Token invalide' }); }
};

const calcCout = (id) => {
  const a = db.prepare('SELECT * FROM couts_achat WHERE vehicule_id=?').get(id) || {};
  const t = db.prepare('SELECT * FROM couts_transport WHERE vehicule_id=?').get(id) || {};
  const p = db.prepare('SELECT * FROM couts_port WHERE vehicule_id=?').get(id) || {};
  const r = db.prepare('SELECT SUM(montant) as total FROM reparations WHERE vehicule_id=?').get(id);
  return (a.prix_bid||0)+(a.frais_copart||0)+(a.towing||0)+(a.autres_usa||0)+
    (t.shipping||0)+(p.dedouanement||0)+(p.debarquement||0)+(p.magasinage||0)+(p.livraison_port||0)+(p.autres_port||0)+(r?.total||0);
};

// ── AUTH
app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body;
  const admin = db.prepare('SELECT * FROM admins WHERE email=?').get(email);
  if (!admin || !bcrypt.compareSync(password, admin.password)) return res.status(401).json({ error: 'Identifiants incorrects' });
  const token = jwt.sign({ id: admin.id, email: admin.email, role: admin.role }, SECRET, { expiresIn: '24h' });
  res.json({ token, admin: { id: admin.id, nom: admin.nom, email: admin.email, role: admin.role } });
});
app.get('/api/auth/me', auth, (req, res) => res.json(db.prepare('SELECT id,nom,email,role FROM admins WHERE id=?').get(req.admin.id)));

// ── VÉHICULES
app.get('/api/vehicules/stats/summary', auth, (req, res) => {
  const total = db.prepare('SELECT COUNT(*) as n FROM vehicules').get().n;
  const en_transit = db.prepare("SELECT COUNT(*) as n FROM vehicules WHERE etat='en_transit'").get().n;
  const en_reparation = db.prepare("SELECT COUNT(*) as n FROM vehicules WHERE etat='en_reparation'").get().n;
  const disponible = db.prepare("SELECT COUNT(*) as n FROM vehicules WHERE etat='disponible'").get().n;
  const vendu = db.prepare("SELECT COUNT(*) as n FROM vehicules WHERE etat='vendu'").get().n;
  const vtc = db.prepare("SELECT COUNT(*) as n FROM vehicules WHERE mode='vtc'").get().n;
  const revenus_revente = db.prepare("SELECT SUM(prix_vente) as t FROM reventes WHERE statut='vendu'").get().t || 0;
  const versements_mois = db.prepare("SELECT SUM(montant_verse) as t FROM versements WHERE strftime('%Y-%m',date)=strftime('%Y-%m','now')").get().t || 0;
  res.json({ total, en_transit, en_reparation, disponible, vendu, vtc, revenus_revente, versements_mois });
});

app.get('/api/vehicules', auth, (req, res) => {
  const vehicules = db.prepare('SELECT * FROM vehicules ORDER BY created_at DESC').all();
  res.json(vehicules.map(v => {
    const cout_total = calcCout(v.id);
    const rev = db.prepare('SELECT * FROM reventes WHERE vehicule_id=?').get(v.id);
    const benefice = rev?.prix_vente ? rev.prix_vente - cout_total : null;
    return { ...v, cout_total, benefice };
  }));
});

app.post('/api/vehicules', auth, (req, res) => {
  const { lot_number,vin,marque,modele,annee,couleur,carburant,transmission,mode,notes,kilometrage } = req.body;
  if (!marque||!modele) return res.status(400).json({ error: 'Marque et modèle obligatoires' });
  const r = db.prepare('INSERT INTO vehicules (lot_number,vin,marque,modele,annee,couleur,carburant,transmission,mode,notes,kilometrage) VALUES (?,?,?,?,?,?,?,?,?,?,?)').run(lot_number,vin,marque,modele,annee,couleur,carburant||'essence',transmission||'automatique',mode||'revente',notes,kilometrage||0);
  db.prepare('INSERT OR IGNORE INTO couts_achat (vehicule_id) VALUES (?)').run(r.lastInsertRowid);
  db.prepare('INSERT OR IGNORE INTO couts_transport (vehicule_id) VALUES (?)').run(r.lastInsertRowid);
  db.prepare('INSERT OR IGNORE INTO couts_port (vehicule_id) VALUES (?)').run(r.lastInsertRowid);
  res.status(201).json({ id: r.lastInsertRowid });
});

app.get('/api/vehicules/:id', auth, (req, res) => {
  const v = db.prepare('SELECT * FROM vehicules WHERE id=?').get(req.params.id);
  if (!v) return res.status(404).json({ error: 'Non trouvé' });
  const achat = db.prepare('SELECT * FROM couts_achat WHERE vehicule_id=?').get(v.id) || {};
  const transport = db.prepare('SELECT * FROM couts_transport WHERE vehicule_id=?').get(v.id) || {};
  const port = db.prepare('SELECT * FROM couts_port WHERE vehicule_id=?').get(v.id) || {};
  const reparations = db.prepare('SELECT * FROM reparations WHERE vehicule_id=? ORDER BY date DESC').all(v.id);
  const revente = db.prepare('SELECT * FROM reventes WHERE vehicule_id=?').get(v.id);
  const total_reparations = reparations.reduce((s,r)=>s+r.montant,0);
  const cout_total = calcCout(v.id);
  res.json({ ...v, achat, transport, port, reparations, total_reparations, revente, cout_total });
});

app.patch('/api/vehicules/:id', auth, (req, res) => {
  const { marque,modele,annee,couleur,etat,mode,notes,kilometrage } = req.body;
  db.prepare('UPDATE vehicules SET marque=COALESCE(?,marque),modele=COALESCE(?,modele),annee=COALESCE(?,annee),couleur=COALESCE(?,couleur),etat=COALESCE(?,etat),mode=COALESCE(?,mode),notes=COALESCE(?,notes),kilometrage=COALESCE(?,kilometrage) WHERE id=?').run(marque,modele,annee,couleur,etat,mode,notes,kilometrage,req.params.id);
  res.json({ success: true });
});

app.put('/api/vehicules/:id/couts-achat', auth, (req, res) => {
  const { prix_bid,frais_copart,towing,autres_usa } = req.body;
  db.prepare('INSERT OR REPLACE INTO couts_achat (vehicule_id,prix_bid,frais_copart,towing,autres_usa) VALUES (?,?,?,?,?)').run(req.params.id,prix_bid||0,frais_copart||0,towing||0,autres_usa||0);
  res.json({ success: true });
});

app.put('/api/vehicules/:id/transport', auth, (req, res) => {
  const { shipping,compagnie,date_depart,date_arrivee_estimee,date_arrivee_reelle,numero_bl } = req.body;
  db.prepare('INSERT OR REPLACE INTO couts_transport (vehicule_id,shipping,compagnie,date_depart,date_arrivee_estimee,date_arrivee_reelle,numero_bl) VALUES (?,?,?,?,?,?,?)').run(req.params.id,shipping||0,compagnie,date_depart,date_arrivee_estimee,date_arrivee_reelle,numero_bl);
  res.json({ success: true });
});

app.put('/api/vehicules/:id/port', auth, (req, res) => {
  const { dedouanement,debarquement,magasinage,livraison_port,autres_port } = req.body;
  db.prepare('INSERT OR REPLACE INTO couts_port (vehicule_id,dedouanement,debarquement,magasinage,livraison_port,autres_port) VALUES (?,?,?,?,?,?)').run(req.params.id,dedouanement||0,debarquement||0,magasinage||0,livraison_port||0,autres_port||0);
  res.json({ success: true });
});

app.post('/api/vehicules/:id/reparations', auth, (req, res) => {
  const { type,description,montant,fournisseur,date } = req.body;
  db.prepare('INSERT INTO reparations (vehicule_id,type,description,montant,fournisseur,date) VALUES (?,?,?,?,?,?)').run(req.params.id,type,description,montant,fournisseur,date||new Date().toISOString().slice(0,10));
  res.status(201).json({ success: true });
});

app.delete('/api/vehicules/:id/reparations/:rid', auth, (req, res) => {
  db.prepare('DELETE FROM reparations WHERE id=? AND vehicule_id=?').run(req.params.rid,req.params.id);
  res.json({ success: true });
});

app.put('/api/vehicules/:id/revente', auth, (req, res) => {
  const { prix_vente,acheteur_nom,acheteur_tel,date_vente,acompte,statut,notes } = req.body;
  db.prepare('INSERT OR REPLACE INTO reventes (vehicule_id,prix_vente,acheteur_nom,acheteur_tel,date_vente,acompte,statut,notes) VALUES (?,?,?,?,?,?,?,?)').run(req.params.id,prix_vente,acheteur_nom,acheteur_tel,date_vente,acompte||0,statut||'en_cours',notes);
  if (statut==='vendu') db.prepare("UPDATE vehicules SET etat='vendu' WHERE id=?").run(req.params.id);
  res.json({ success: true });
});

// ── CHAUFFEURS
app.get('/api/chauffeurs', auth, (req, res) => {
  res.json(db.prepare('SELECT c.*,v.marque,v.modele FROM chauffeurs c LEFT JOIN vehicules v ON c.vehicule_id=v.id ORDER BY c.created_at DESC').all());
});

app.post('/api/chauffeurs', auth, (req, res) => {
  const { nom,telephone,email,permis,vehicule_id,montant_journalier,date_debut,notes } = req.body;
  if (!nom) return res.status(400).json({ error: 'Nom obligatoire' });
  const r = db.prepare('INSERT INTO chauffeurs (nom,telephone,email,permis,vehicule_id,montant_journalier,date_debut,notes) VALUES (?,?,?,?,?,?,?,?)').run(nom,telephone,email,permis,vehicule_id,montant_journalier||0,date_debut,notes);
  if (vehicule_id) db.prepare("UPDATE vehicules SET etat='vtc',mode='vtc' WHERE id=?").run(vehicule_id);
  res.status(201).json({ id: r.lastInsertRowid });
});

app.patch('/api/chauffeurs/:id', auth, (req, res) => {
  const { nom,telephone,montant_journalier,statut,notes } = req.body;
  db.prepare('UPDATE chauffeurs SET nom=COALESCE(?,nom),telephone=COALESCE(?,telephone),montant_journalier=COALESCE(?,montant_journalier),statut=COALESCE(?,statut),notes=COALESCE(?,notes) WHERE id=?').run(nom,telephone,montant_journalier,statut,notes,req.params.id);
  res.json({ success: true });
});

app.get('/api/chauffeurs/:id/versements', auth, (req, res) => {
  res.json(db.prepare('SELECT * FROM versements WHERE chauffeur_id=? ORDER BY date DESC').all(req.params.id));
});

app.post('/api/chauffeurs/:id/versements', auth, (req, res) => {
  const { date,montant_verse,montant_attendu,kilometrage,notes } = req.body;
  const ch = db.prepare('SELECT * FROM chauffeurs WHERE id=?').get(req.params.id);
  const r = db.prepare('INSERT INTO versements (chauffeur_id,vehicule_id,date,montant_attendu,montant_verse,kilometrage,statut,notes) VALUES (?,?,?,?,?,?,?,?)').run(req.params.id,ch?.vehicule_id,date||new Date().toISOString().slice(0,10),montant_attendu||ch?.montant_journalier||0,montant_verse,kilometrage||0,montant_verse>=(montant_attendu||0)?'paye':'partiel',notes);
  if (kilometrage&&ch?.vehicule_id) db.prepare('UPDATE vehicules SET kilometrage=? WHERE id=?').run(kilometrage,ch.vehicule_id);
  res.status(201).json({ id: r.lastInsertRowid });
});

app.get('/api/chauffeurs/:id/stats', auth, (req, res) => {
  const total_verse = db.prepare('SELECT SUM(montant_verse) as t FROM versements WHERE chauffeur_id=?').get(req.params.id).t||0;
  const total_attendu = db.prepare('SELECT SUM(montant_attendu) as t FROM versements WHERE chauffeur_id=?').get(req.params.id).t||0;
  const nb_jours = db.prepare('SELECT COUNT(*) as n FROM versements WHERE chauffeur_id=?').get(req.params.id).n;
  res.json({ total_verse, total_attendu, nb_jours, manquant: total_attendu-total_verse });
});

// ── HEALTH
app.get('/api/health', (req, res) => res.json({ status: 'ok', service: 'EDGE CARS' }));
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));

app.listen(PORT, () => console.log(`✅ EDGE CARS API — Port ${PORT}`));
