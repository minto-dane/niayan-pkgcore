-- SPDX-License-Identifier: BSD-3-Clause
with MC_SHA256;
package body MC_Backups with SPARK_Mode is
   function Valid (P : Policy) return Boolean is
     (P.Scope /= Zero_Identity and then P.Dataset /= Zero_Identity
      and then P.Lineage /= Zero_Identity and then P.Now_Lower <= P.Now_Upper
      and then P.Minimum_Trust_Epoch > 0 and then P.Maximum_Test_Age > 0
      and then P.Minimum_Domains <= P.Minimum_Copies
      and then P.Immutable_For <= Counter'Last - P.Now_Upper);
   function Valid_Catalog (C : Catalog; Count : Natural) return Boolean is
   begin
      if Count = 0 or else Count > Capacity then return False; end if;
      for I in 1..Count loop
         if C (I).Manifest = Zero_Digest or else C (I).Scope = Zero_Identity
           or else C (I).Dataset = Zero_Identity or else C (I).Lineage = Zero_Identity
           or else C (I).Payload = Zero_Digest or else C (I).From_Position > C (I).Through_Position
         then return False; end if;
         if C (I).Full /= (C (I).Parent = Zero_Digest)
           or else (C (I).Full and then C (I).From_Position /= 0) then return False; end if;
         for J in 1..I-1 loop if C (I).Manifest = C (J).Manifest then return False; end if; end loop;
      end loop;
      return True;
   end Valid_Catalog;
   procedure Chain (C : Catalog; Count, Terminal : Natural; Members : out Selection;
      Commitment : out Digest; Status : out Outcome) is
      Here : Index; Parent : Natural range 0 .. Capacity;
      Path : array (Index) of Index := (others => 1);
      Depth : Natural range 0 .. Capacity := 0; B : Bytes (1..72) := (others => 0);
   begin
      Members := (others => False); Commitment := Zero_Digest; Status := Invalid_Input;
      if not Valid_Catalog (C,Count) or else Terminal = 0 or else Terminal > Count then return; end if;
      Here := Terminal;
      loop
         if Depth = Capacity or else Members (Here) then Status := Corrupt; return; end if;
         Members (Here) := True; Depth := Depth+1; Path (Depth) := Here;
         exit when C (Here).Full;
         Parent := 0;
         for I in 1..Count loop
            if C (I).Manifest = C (Here).Parent then Parent := I; exit; end if;
         end loop;
         if Parent = 0 or else C (Parent).Scope /= C (Here).Scope
           or else C (Parent).Dataset /= C (Here).Dataset or else C (Parent).Lineage /= C (Here).Lineage
           or else C (Parent).Through_Position /= C (Here).From_Position
           or else C (Parent).Completed_At > C (Here).Completed_At
         then Status := Corrupt; return; end if;
         Here := Parent;
      end loop;
      B (1..8) := (77,67,66,67,72,48,48,49);
      for I in reverse 1..Depth loop
         B (9..40) := C (Path (I)).Manifest; B (41..72) := Commitment;
         Commitment := MC_SHA256.Hash (B);
      end loop;
      Status := OK;
   end Chain;
   function Usable (P : Policy; B : Backup) return Boolean is
      Total, Domains : Natural := 0; Distinct : Boolean;
      Accepted : array (Copy_Index) of Boolean := (others => False);
   begin
      if not Valid (P) or else B.Scope /= P.Scope or else B.Dataset /= P.Dataset
        or else B.Lineage /= P.Lineage or else not B.Authenticated or else not B.Header_Payload_Bound
        or else not B.Key_Available or else B.Key_Revoked or else B.Integrity_Incident
        or else B.Trust_Epoch < P.Minimum_Trust_Epoch or else B.Completed_At > P.Now_Lower
      then return False; end if;
      for I in Copy_Index loop
         if B.Locations (I).Store_ID /= Zero_Identity then
            for J in 1..I-1 loop
               if B.Locations (I).Store_ID = B.Locations (J).Store_ID then return False; end if;
            end loop;
         end if;
         if B.Locations (I).Authenticated and then B.Locations (I).Integrity_Verified
           and then B.Locations (I).Durable and then B.Locations (I).Store_ID /= Zero_Identity
           and then B.Locations (I).Domain_ID > 0 and then B.Locations (I).Receipt_Hash /= Zero_Digest
           and then B.Locations (I).Object_Hash = B.Payload
           and then B.Locations (I).Valid_Until > P.Now_Upper
           and then B.Locations (I).Immutable_Until >= P.Now_Upper + P.Immutable_For
         then
            Accepted (I) := True; Total := Total+1; Distinct := True;
            for J in 1..I-1 loop
               if Accepted (J) and then B.Locations (J).Domain_ID = B.Locations (I).Domain_ID
               then Distinct := False; end if;
            end loop;
            if Distinct then Domains := Domains+1; end if;
         end if;
      end loop;
      return Total >= P.Minimum_Copies and then Domains >= P.Minimum_Domains;
   end Usable;
   procedure Restore_Set (P : Policy; C : Catalog; Count, Terminal : Natural;
      Members : out Selection; Status : out Outcome) is
      D : Digest;
   begin
      Chain (C,Count,Terminal,Members,D,Status); if Status /= OK then return; end if;
      Status := Denied;
      if not Valid (P) or else C (Terminal).Through_Position < P.Required_Position
        or else C (Terminal).Restore_Test_Chain /= D
        or else C (Terminal).Tested_At < C (Terminal).Completed_At
        or else C (Terminal).Tested_At > P.Now_Lower
        or else P.Now_Upper - C (Terminal).Tested_At > P.Maximum_Test_Age
      then return; end if;
      for I in 1..Count loop if Members (I) and then not Usable (P,C (I)) then return; end if; end loop;
      Status := OK;
   end Restore_Set;
   procedure Choose (P : Policy; C : Catalog; Count : Natural;
      Terminal : out Natural; Members : out Selection; Status : out Outcome) is
      Candidate : Selection; S : Outcome;
   begin
      Terminal := 0; Members := (others => False); Status := Invalid_Input;
      if not Valid (P) or else not Valid_Catalog (C,Count) then return; end if;
      for I in 1..Count loop
         pragma Loop_Invariant(Terminal in 0 .. Capacity);
         Restore_Set (P,C,Count,I,Candidate,S);
         if S = OK and then (Terminal = 0
           or else C (I).Through_Position > C (Terminal).Through_Position
           or else (C (I).Through_Position = C (Terminal).Through_Position
             and then C (I).Tested_At > C (Terminal).Tested_At))
         then Terminal := I; Members := Candidate; end if;
      end loop;
      Status := (if Terminal = 0 then Denied else OK);
   end Choose;
end MC_Backups;
