-- SPDX-License-Identifier: MIT
with MC_Control_Codec; with MC_Contract_Profile; with MC_Atomic;
with MC_Posix; with MC_Authentic; with MC_SHA256; with MC_Clock; with MC_Hex;
package body MC_Control_IO with SPARK_Mode => Off is
   use type MC_FS.Entry_Kind; use type Word;
   procedure Private_Read (R : MC_FS.Root; Name : String;
      Data : out Bytes; Status : out Outcome) is
      Info : MC_FS.Entry_Info; Used : Natural;
   begin
      Data := (others => 0);
      MC_FS.Stat (R,Name,Info,Status); if Status /= OK then return; end if;
      if Info.Kind /= MC_FS.Regular or else Info.Links /= 1
        or else Info.Mode not in 8#400# | 8#600#
        or else Info.UID /= Word (MC_Posix.Euid) or else Info.Size /= Counter (Data'Length)
      then Status := Denied; return; end if;
      MC_Atomic.Read (R,Name,Data,Used,Status);
      if Status = OK and then Used /= Data'Length then Status := Corrupt; end if;
   end Private_Read;
   procedure Authority (R : MC_FS.Root; Scope : Identity; A : out MC_Control.Authority;
      Hash : out Digest; Status : out Outcome) is
      B : MC_Control_Codec.Authority_Frame;
   begin
      Hash := Zero_Digest; A := (others => <>);
      Private_Read (R,"control-authorities.bin",B,Status); if Status /= OK then return; end if;
      MC_Control_Codec.Decode (B,A,Status); if Status /= OK then return; end if;
      if A.Scope /= Scope or else A.Contract /= MC_Contract_Profile.Fingerprint
      then Status := Denied; return; end if; Hash := MC_SHA256.Hash (B);
   end Authority;
   procedure Read_State (Directory : MC_FS.Root; Scope : Identity;
      S : out MC_Control.State; Fingerprint : out Digest; Status : out Outcome) is
      A : MC_Control.Authority; AH : Digest; B : MC_Control_Codec.State_Frame;
   begin
      S := (others => <>); Fingerprint := Zero_Digest;
      Authority (Directory,Scope,A,AH,Status); if Status /= OK then return; end if;
      Private_Read (Directory,"control-state.bin",B,Status); if Status /= OK then return; end if;
      MC_Control_Codec.Decode (B,S,Status); if Status /= OK then return; end if;
      if S.Scope /= Scope or else S.Contract /= A.Contract or else S.Authority_Digest /= AH
      then Status := Denied; return; end if; Fingerprint := MC_SHA256.Hash (B);
   end Read_State;
   procedure Check (Directory : MC_FS.Root; Scope : Identity;
      Action : MC_Control.Operation; Status : out Outcome) is
      S : MC_Control.State; D : Digest;
   begin
      Read_State (Directory,Scope,S,D,Status);
      if Status = OK and then not MC_Control.Permits (S.Current,Action) then Status := Denied; end if;
   end Check;
   procedure Preserve (R : MC_FS.Root; Name : String; Data : Bytes; Status : out Outcome) is
      Existing : Bytes (1..Data'Length); Used : Natural;
   begin
      MC_Atomic.Write (R,Name,Data,True,Status);
      if Status = Conflict then
         MC_Atomic.Read (R,Name,Existing,Used,Status);
         if Status = OK and then (Used /= Data'Length or else Existing /= Data)
         then Status := Conflict; end if;
      end if;
   end Preserve;
   procedure Submit (Directory_Path : String; Scope : Identity;
      Raw_Proposal : Bytes; Signatures : Signature_Bundle; Status : out Outcome) is
      R : MC_FS.Root; Lock : MC_FS.File; A : MC_Control.Authority;
      Before, After : MC_Control.State; P : MC_Control.Proposal;
      AH, BH : Digest := Zero_Digest; V : MC_Control.Verified_Set := (others => False);
      Boot : Identity; Now : Counter; Info : MC_FS.Entry_Info; Genesis : Boolean;
      Record_Data : Bytes (1..832); Saved : Bytes (1..832); Used : Natural;
      procedure Done is begin MC_FS.Close (Lock); MC_FS.Close (R); end Done;
   begin
      Status := Invalid_Input;
      if Raw_Proposal'First /= 1 or else Raw_Proposal'Length /= 320 then return; end if;
      MC_Control_Codec.Decode (Raw_Proposal,P,Status); if Status /= OK then return; end if;
      MC_FS.Open_Root (Directory_Path,R,Status,Private_Only => True); if Status /= OK then return; end if;
      MC_FS.Open_Locked (R,"control.lock",Lock,Status,
        Create_If_Missing => P.Expected_State=Zero_Digest and then P.Expected_Revision=0); if Status /= OK then Done; return; end if;
      Authority (R,Scope,A,AH,Status); if Status /= OK then Done; return; end if;
      for I in MC_Control.Signer_Index loop
         declare L : constant Positive := 1+(I-1)*64; begin
            if not Is_Zero (Signatures (L..L+63)) then
               if I > A.Count then Status := Denied; Done; return; end if;
               MC_Authentic.Verify ("MC-CONTROL-v1",Raw_Proposal,Signatures (L..L+63),A.Keys (I).Public_Key,Status);
               if Status /= OK then Done; return; end if; V (I) := True;
            end if;
         end;
      end loop;
      MC_FS.Stat (R,"control-state.bin",Info,Status); if Status /= OK then Done; return; end if;
      Genesis := Info.Kind = MC_FS.Absent;
      if not Genesis then
         Read_State (R,Scope,Before,BH,Status); if Status /= OK then Done; return; end if;
      end if;
      Record_Data (1..320) := Raw_Proposal; Record_Data (321..832) := Signatures;
      if not Genesis and then Before.Last_Request = P.Request_ID then
         -- Exact acknowledged retry only. Cannot execute a different change under
         -- a reused request identity. Signature verification already ran above.
         Private_Read (R,"control-request-" & MC_Hex.Encode (P.Request_ID) & ".bin",Saved,Status);
         if Status = OK and then Saved /= Record_Data then Status := Conflict; end if;
         Done; return;
      end if;
      MC_Clock.Read_Boot_ID (Boot,Status); if Status /= OK then Done; return; end if;
      MC_Clock.Boottime_Milliseconds (Now,Status); if Status /= OK then Done; return; end if;
      MC_Control.Decide (A,AH,Before,BH,Genesis,P,V,Boot,Now,After,Status);
      if Status /= OK then Done; return; end if;
      if not Genesis then
         Preserve (R,"control-history-" & MC_Hex.Encode (BH) & ".bin",MC_Control_Codec.Encode (Before),Status);
         if Status /= OK then Done; return; end if;
      end if;
      Preserve (R,"control-request-" & MC_Hex.Encode (P.Request_ID) & ".bin",Record_Data,Status);
      if Status /= OK then Done; return; end if;
      Preserve (R,"control-history-" & MC_Hex.Encode (MC_SHA256.Hash (MC_Control_Codec.Encode (After))) & ".bin",
         MC_Control_Codec.Encode (After),Status); if Status /= OK then Done; return; end if;
      -- Bound lifetime is rechecked after all potentially slow archive writes.
      MC_Clock.Boottime_Milliseconds (Now,Status); if Status /= OK then Done; return; end if;
      if Now >= P.Expires then Status := Stale; Done; return; end if;
      MC_Atomic.Write (R,"control-state.bin",MC_Control_Codec.Encode (After),False,Status);
      if Status = OK then
         declare B : MC_Control_Codec.State_Frame; begin
            MC_Atomic.Read (R,"control-state.bin",B,Used,Status);
            if Status /= OK or else Used /= B'Length or else B /= MC_Control_Codec.Encode (After)
            then Status := Indeterminate; end if;
         end;
      end if; Done;
   exception when others => Done; Status := Indeterminate;
   end Submit;
end MC_Control_IO;
