import mongoose from 'mongoose';

// Define schema
const completedWorkSchema = new mongoose.Schema({
  referralId: {
    type: mongoose.Schema.Types.ObjectId,
    required: true
  },
  completedAt: {
    type: Date,
    default: Date.now
  }
});

// Create model
const CompletedWork = mongoose.model('CompletedWork', completedWorkSchema);

export default CompletedWork;
