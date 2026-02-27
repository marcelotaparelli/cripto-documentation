# cripto-documentation

# Guia de Criptografia e Autenticação em Node.js

Este documento descreve o processo técnico de proteção de credenciais, desde o recebimento da senha em texto plano até o armazenamento seguro em banco de dados e a subsequente autorização via tokens.

---

## 1. Conceitos Fundamentais

### Salt (Sal)

O salt é um dado aleatório adicionado à senha antes do processo de hashing. Seu objetivo é garantir que dois usuários com a mesma senha possuam hashes diferentes no banco de dados, protegendo contra ataques de Rainbow Tables.

### Hashing (Função de Resumo)

Diferente da criptografia, o hashing é um processo unidirecional. Uma vez gerado o hash, não é possível "descriptografá-lo" para obter a senha original. O algoritmo recomendado para senhas é o **bcrypt** ou **argon2**, devido ao fator de custo (work factor) que dificulta ataques de força bruta.

---

## 2. Fluxo de Armazenamento (Registro)

1. O cliente envia a senha em texto plano via HTTPS.
2. O servidor gera um salt aleatório.
3. O servidor concatena a senha com o salt e gera o hash.
4. O hash resultante (que já inclui o salt internamente no caso do bcrypt) é armazenado no banco de dados.

---

## 3. Fluxo de Verificação (Login)

1. O servidor recupera o hash armazenado para o usuário informado.
2. O servidor utiliza a mesma função de hash na senha fornecida no login, usando o salt original.
3. Se o novo hash gerado for idêntico ao armazenado, a autenticação é válida.

---

## 4. Implementação Técnica

Abaixo, a implementação utilizando a biblioteca `bcrypt` para hashing e `jsonwebtoken` (JWT) para autorização.

### Dependências Necessárias

```bash
npm install bcrypt jsonwebtoken

```

### Módulo de Segurança (auth.service.js)

```javascript
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const SALT_ROUNDS = 10;
const JWT_SECRET = 'sua_chave_secreta_aqui';

/**
 * Transforma uma senha em texto plano em um hash seguro.
 */
async function hashPassword(password) {
    try {
        const salt = await bcrypt.genSalt(SALT_ROUNDS);
        const hash = await bcrypt.hash(password, salt);
        return hash;
    } catch (error) {
        throw new Error('Erro ao processar senha');
    }
}

/**
 * Compara a senha enviada com o hash salvo no banco.
 */
async function verifyPassword(password, hash) {
    return await bcrypt.compare(password, hash);
}

/**
 * Gera um token JWT para autorização.
 */
function generateToken(userPayload) {
    return jwt.sign(
        { id: userPayload.id, email: userPayload.email },
        JWT_SECRET,
        { expiresIn: '8h' }
    );
}

/**
 * Middleware para validar o token nas rotas protegidas.
 */
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) return res.status(401).json({ message: 'Token não fornecido' });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ message: 'Token inválido ou expirado' });
        req.user = user;
        next();
    });
}

module.exports = {
    hashPassword,
    verifyPassword,
    generateToken,
    authenticateToken
};

```

---

## 5. Resumo de Funções e Utilização

### No Registro do Usuário

Ao salvar o usuário no banco de dados (ex: MongoDB ou PostgreSQL):

```javascript
const hash = await hashPassword(req.body.password);
// Salvar 'hash' no campo 'password' do banco de dados

```

### No Login

Ao validar as credenciais:

```javascript
const user = await findUserByEmail(req.body.email);
const isValid = await verifyPassword(req.body.password, user.password);

if (isValid) {
    const token = generateToken(user);
    res.json({ token });
} else {
    res.status(401).send('Credenciais inválidas');
}

```

### Na Proteção de Rotas (Autorização)

Para garantir que apenas usuários logados acessem um recurso:

```javascript
app.get('/perfil', authenticateToken, (req, res) => {
    // req.user contém os dados extraídos do token
    res.json({ user: req.user });
});

```

---

## 6. Boas Práticas de Segurança

1. **HTTPS**: Nunca trafegue senhas ou tokens em conexões HTTP puras.
2. **JWT Secret**: Armazene a chave secreta em variáveis de ambiente (.env) e nunca a exponha no código fonte.
3. **Expiração**: Utilize tempos de expiração curtos para os tokens e implemente Refresh Tokens para melhor experiência do usuário.
4. **Tratamento de Erros**: Não informe ao usuário se o erro foi no e-mail ou na senha especificamente (use "E-mail ou senha incorretos") para evitar enumeração de usuários.

---

Deseja que eu implemente a lógica de **Refresh Tokens** para manter a sessão do usuário ativa com mais segurança na sua VPS?
