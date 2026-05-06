import mongoose from 'mongoose';
import bcrypt from 'bcrypt';

const userSchema = new mongoose.Schema({
    username: { 
        type: String, 
        required: true, 
        unique: true, // Esto asegura que no haya dos pilotos con el mismo nombre
        trim: true 
    },
    password: { 
        type: String, 
        required: true 
    }
}, { 
    timestamps: true 
});

// Si la contraseña es nueva, la encripta
userSchema.pre('save', async function() {
    // Si no han cambiado la contraseña, termina aquí y sigue el guardado normal
    if (!this.isModified('password')) return;
    
    // Genera un "salt" (ruido aleatorio) y encripta
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
     
});

// Función auxiliar para comparar la contraseña del login con la encriptada
userSchema.methods.comparePassword = async function(candidatePassword) {
    return await bcrypt.compare(candidatePassword, this.password);
};

export default mongoose.model('User', userSchema);