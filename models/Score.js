import mongoose from 'mongoose';

const scoreSchema = new mongoose.Schema({
    usuario: { 
        type: String, 
        required: true 
    },
    puntos: { 
        type: Number, 
        required: true 
    },
    fecha: { 
        type: Date, 
        default: Date.now // Se pone la fecha actual automáticamente
    }
});

export default mongoose.model('Score', scoreSchema);