import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';

// Re-importamos el secreto. Asegúrate de que coincida con el de index.ts
const JWT_SECRET = process.env.JWT_SECRET || 'una-frase-secreta-muy-dificil-de-adivinar';

// Extendemos el tipo 'Request' de Express para que acepte nuestra info de usuario
export interface AuthRequest extends Request {
    user?: {
        userId: string;
        username: string;
    };
}

export const authMiddleware = (req: AuthRequest, res: Response, next: NextFunction) => {
    // 1. Obtener el token del header 'Authorization'
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ message: 'Acceso denegado. No se proveyó un token.' });
    }

    const token = authHeader.split(' ')[1]; // Nos quedamos solo con el token

    try {
        // 2. Verificar el token con el secreto
        const payload = jwt.verify(token, JWT_SECRET) as { userId: string; username: string };

        // 3. Si es válido, añadimos la info del usuario al objeto 'req'
        req.user = payload;
        
        // 4. Dejamos que la petición continúe hacia el endpoint
        next();
    } catch (error) {
        res.status(401).json({ message: 'Token inválido o expirado.' });
    }
};