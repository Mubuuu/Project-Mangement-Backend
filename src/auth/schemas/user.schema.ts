/* eslint-disable prettier/prettier */
import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';

@Schema({
  timestamps: true,
})
export class User {
  @Prop({required:true})   
  username: string;
  @Prop({ unique: [true, 'Duplicate email entered'] })
  email: string;
  @Prop({required:true})
  password: string;
}

export const userSchema = SchemaFactory.createForClass(User)