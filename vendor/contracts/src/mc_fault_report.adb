-- SPDX-License-Identifier: MIT
with MC_Codec; with MC_SHA256;
package body MC_Fault_Report with SPARK_Mode is
   use type Wide; use type Byte;
   Magic : constant Bytes := (16#4D#,16#43#,16#46#,16#41#,16#55#,16#4C#,16#54#,16#31#);
   function Encode (F : MC_Faults.Fault) return Frame is
      B : Frame := (others => 0);
      function Bit (V : Boolean) return Byte is (if V then 1 else 0);
   begin
      B (1 .. 8) := Magic;
      B (9 .. 24) := F.Cluster_ID; B (25 .. 40) := F.Node_ID;
      B (41 .. 56) := F.Resource_ID; B (57 .. 72) := F.Boot_ID;
      B (73 .. 104) := F.Policy; B (105 .. 136) := F.Syndrome;
      MC_Codec.Put64 (B, 137, Wide (F.Sequence));
      MC_Codec.Put64 (B, 145, Wide (F.Observed_At));
      MC_Codec.Put64 (B, 153, Wide (F.Expires_At));
      MC_Codec.Put64 (B, 161, Wide (F.Occurrences));
      B (169) := Byte (MC_Faults.Domain'Pos (F.Kind));
      B (170) := Byte (MC_Faults.Severity'Pos (F.Level));
      B (171) := Byte (MC_Faults.Persistence'Pos (F.Nature));
      B (172) := Byte (MC_Faults.Evidence_Quality'Pos (F.Quality));
      B (173) := Bit (F.Corrected); B (174) := Bit (F.Data_At_Risk);
      B (175) := Bit (F.Execution_At_Risk);
      B (289 .. 320) := MC_SHA256.Hash (B (1 .. 288));
      return B;
   end Encode;
   procedure Decode (B : Bytes; F : out MC_Faults.Fault; Status : out Outcome) is
      X : Frame;
      Offsets : constant array (Positive range 1 .. 4) of Positive := (137,145,153,161);
   begin
      F := (others => <>); Status := Corrupt;
      if B'Length /= Record_Size or else B'First /= 1 then return; end if; X := B;
      if X (1 .. 8) /= Magic or else X (289 .. 320) /= MC_SHA256.Hash (X (1 .. 288)) then return; end if;
      for J in 176 .. 288 loop if X (J) /= 0 then return; end if; end loop;
      if X (169) > Byte (MC_Faults.Domain'Pos (MC_Faults.Domain'Last))
        or else X (170) > Byte (MC_Faults.Severity'Pos (MC_Faults.Severity'Last))
        or else X (171) > Byte (MC_Faults.Persistence'Pos (MC_Faults.Persistence'Last))
        or else X (172) > Byte (MC_Faults.Evidence_Quality'Pos (MC_Faults.Evidence_Quality'Last))
      then return; end if;
      for J in 173 .. 175 loop if X (J) > 1 then return; end if; end loop;
      for O of Offsets loop if MC_Codec.U64 (X,O) > Wide (Counter'Last) then return; end if; end loop;
      F.Cluster_ID := X (9 .. 24); F.Node_ID := X (25 .. 40); F.Resource_ID := X (41 .. 56); F.Boot_ID := X (57 .. 72);
      F.Policy := X (73 .. 104); F.Syndrome := X (105 .. 136);
      F.Sequence := Counter (MC_Codec.U64 (X,137)); F.Observed_At := Counter (MC_Codec.U64 (X,145));
      F.Expires_At := Counter (MC_Codec.U64 (X,153)); F.Occurrences := Counter (MC_Codec.U64 (X,161));
      F.Kind := MC_Faults.Domain'Val (X (169)); F.Level := MC_Faults.Severity'Val (X (170));
      F.Nature := MC_Faults.Persistence'Val (X (171)); F.Quality := MC_Faults.Evidence_Quality'Val (X (172));
      F.Corrected := X (173) = 1; F.Data_At_Risk := X (174) = 1; F.Execution_At_Risk := X (175) = 1;
      if not MC_Faults.Valid (F) or else Encode (F) /= X then return; end if;
      Status := OK;
   end Decode;
end MC_Fault_Report;
