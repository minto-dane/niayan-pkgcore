-- SPDX-License-Identifier: BSD-3-Clause
with MC_Types; use MC_Types;
with MC_FS; with MC_Log_Format;
package MC_Log with SPARK_Mode => Off is
   type Journal is limited private;
   Max_Records : constant Counter := 1_048_576;
   procedure Open(R : MC_FS.Root; Path : String; Root_ID : Identity;
                  J : in out Journal; Status : out Outcome;
                  Create_If_Missing : Boolean := True);
   procedure Read(J : Journal; Index : Counter; E : out MC_Log_Format.Log_Entry; Status : out Outcome);
   procedure Append(J : in out Journal; E : in out MC_Log_Format.Log_Entry; Status : out Outcome);
   function Length(J : Journal) return Counter;
   function Head(J : Journal) return Digest;
   function Can_Append (J : Journal; Records : Counter;
                        After_Tail_Repair : Boolean := False) return Boolean;
   -- Admission reserves intent AND result under the exclusive journal lock.
   -- After_Tail_Repair only checks capacity; it does not authorize truncation.
   function Has_Torn_Tail(J : Journal) return Boolean;
   procedure Export_Tail(J : Journal; Data : out Bytes; Used : out Natural; Status : out Outcome);
   procedure Repair_Tail(J : in out Journal; Preserved_Tail : Digest; Status : out Outcome);
   procedure Close(J : in out Journal);
   -- Repair is only for a partial final record, never for an invalid full record.
   -- Caller must durably preserve Export_Tail in its CAS before supplying its digest.
   -- Application recovery re-observes effects after repair; no effect is inferred undone.
private
   type Journal is limited record
      F : MC_FS.File;
      Root_ID : Identity := Zero_Identity;
      Count : Counter := 0;
      Last_Digest : Digest := Zero_Digest;
      Tail_Bytes : Natural range 0..255 := 0;
      Opened, Poisoned : Boolean := False;
   end record;
end MC_Log;
