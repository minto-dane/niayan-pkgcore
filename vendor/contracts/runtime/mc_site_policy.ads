-- SPDX-License-Identifier: BSD-3-Clause
with MC_Types; use MC_Types;
with MC_Authorization; with MC_Signatures; with MC_Witness; with MC_FS;
package MC_Site_Policy with SPARK_Mode => Off is
   type Witness_Keys is array(MC_Witness.Fact) of MC_Signatures.Public_Key;
   type Policy is record
      Scope : MC_Authorization.Scope;
      Root_ID : Identity := Zero_Identity;
      Request_Key : MC_Signatures.Public_Key := (others=>0);
      Observers : Witness_Keys := (others=>(others=>0));
      Contract : Digest := Zero_Digest;
      Serial, Valid_Until : Counter := 0;
      Maximum_Witness_Age : Counter := 5_000;
   end record;
   Size : constant := 512;
   subtype Frame is Bytes(1..Size);
   function Encode(P : Policy) return Frame;
   procedure Decode(B : Bytes; P : out Policy; Status : out Outcome);
   procedure Load(Directory : MC_FS.Root; P : out Policy; Fingerprint : out Digest; Status : out Outcome);
   -- Local bootstrap file policy.bin MUST be on a protected, non-rollback volume.
   -- Loading is administrator trust via owner+mode, not a network authentication step.
   -- Boot_ID is deliberately not persisted; each request must name the current boot.
end MC_Site_Policy;
