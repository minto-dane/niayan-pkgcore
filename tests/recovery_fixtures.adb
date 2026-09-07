-- SPDX-License-Identifier: MIT
package body Recovery_Fixtures with SPARK_Mode => Off is
   procedure Make (P : out MC_Backups.Policy; C : out MC_Backups.Catalog; Status : out Outcome) is
      Members : MC_Backups.Selection; H : Digest;
   begin
      P := (others => <>); C := (others => <>);
      P.Scope := (others => 1); P.Dataset := (others => 2); P.Lineage := (others => 3);
      P.Now_Lower := 1_000; P.Now_Upper := 1_000; P.Required_Position := 10;
      P.Minimum_Trust_Epoch := 1; P.Maximum_Test_Age := 1_000; P.Immutable_For := 10;
      for I in 1..4 loop
         C (I).Scope := P.Scope; C (I).Dataset := P.Dataset; C (I).Lineage := P.Lineage;
         C (I).Manifest := (others => Byte (10+I)); C (I).Payload := (others => Byte (20+I));
         C (I).Full := True; C (I).Through_Position := Counter (I*10);
         C (I).Completed_At := Counter (100+I); C (I).Tested_At := 900;
         C (I).Trust_Epoch := 1; C (I).Authenticated := True; C (I).Header_Payload_Bound := True;
         C (I).Key_Available := True; C (I).Key_Revoked := False; C (I).Integrity_Incident := False;
         C (I).Pinned := False; C (I).In_Use := False; C (I).Legal_Hold := False;
         for J in 1..2 loop
            C (I).Locations (J).Store_ID := (others => Byte (30+J)); C (I).Locations (J).Domain_ID := J;
            C (I).Locations (J).Object_Hash := C (I).Payload;
            C (I).Locations (J).Receipt_Hash := (others => Byte (40+J));
            C (I).Locations (J).Valid_Until := 2_000; C (I).Locations (J).Immutable_Until := 2_000;
            C (I).Locations (J).Authenticated := True; C (I).Locations (J).Integrity_Verified := True;
            C (I).Locations (J).Durable := True;
         end loop;
      end loop;
      for I in 1..4 loop
         MC_Backups.Chain (C,4,I,Members,H,Status); if Status /= OK then return; end if;
         C (I).Restore_Test_Chain := H;
      end loop;
   end Make;
end Recovery_Fixtures;
