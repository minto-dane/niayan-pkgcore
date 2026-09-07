-- SPDX-License-Identifier: MIT
with MC_FS; with MC_Atomic; with MC_Checkpoint; with MC_SHA256; with MC_Hex;
with MC_Contract_Profile;
package body MC_Checkpoint_Store with SPARK_Mode => Off is
   use type MC_FS.Entry_Kind;
   procedure Read_Descriptor (R : MC_FS.Root; Name : String;
      D : out MC_Checkpoint.Descriptor; Status : out Outcome) is
      B : MC_Checkpoint.Frame; Used : Natural;
   begin
      D := (others => <>); MC_Atomic.Read (R,Name,B,Used,Status);
      if Status /= OK then return; end if;
      if Used /= B'Length then Status := Corrupt; return; end if;
      MC_Checkpoint.Decode (B,D,Status);
      if Status = OK and then D.Contract /= MC_Contract_Profile.Fingerprint then Status := Unsupported; end if;
   end Read_Descriptor;
   procedure Read_Payload (R : MC_FS.Root; D : MC_Checkpoint.Descriptor;
      B : out Bytes; Used : out Natural; Status : out Outcome) is
   begin
      Used := 0; B := (others => 0);
      if Counter (B'Length) < D.Payload_Size then Status := Exhausted; return; end if;
      MC_Atomic.Read (R,"snapshot-" & MC_Hex.Encode (D.Payload) & ".bin",B,Used,Status);
      if Status /= OK then return; end if;
      if Used = 0 or else Counter (Used) /= D.Payload_Size
        or else MC_SHA256.Hash (B (B'First..B'First+Used-1)) /= D.Payload
      then Status := Corrupt; return; end if;
      Validate_State (D,B (B'First..B'First+Used-1),Status);
   end Read_Payload;
   procedure Keep (R : MC_FS.Root; Name : String; B : Bytes; Status : out Outcome) is
      Saved : Bytes (1..B'Length); Used : Natural;
   begin
      MC_Atomic.Write (R,Name,B,True,Status);
      if Status = Conflict then
         MC_Atomic.Read (R,Name,Saved,Used,Status);
         if Status = OK and then (Used /= B'Length or else Saved /= B) then Status := Conflict; end if;
      end if;
   end Keep;
   procedure Load (Directory : String; Root_ID, Stream_ID : Identity;
      D : out MC_Checkpoint.Descriptor; Payload : out Bytes; Used : out Natural;
      Status : out Outcome) is
      R : MC_FS.Root;
   begin
      Used := 0; Payload := (others => 0); D := (others => <>);
      MC_FS.Open_Root (Directory,R,Status,Private_Only => True); if Status /= OK then return; end if;
      Read_Descriptor (R,"checkpoint-current.bin",D,Status);
      if Status = OK and then (D.Root_ID /= Root_ID or else D.Stream_ID /= Stream_ID) then Status := Denied; end if;
      if Status = OK then Check_Anchor (D,MC_SHA256.Hash (MC_Checkpoint.Encode (D)),Status); end if;
      if Status = OK then Read_Payload (R,D,Payload,Used,Status); end if;
      MC_FS.Close (R);
   exception when others => MC_FS.Close (R); Status := Indeterminate;
   end Load;
   procedure Publish (Directory : String; Expected : Digest;
      D : MC_Checkpoint.Descriptor; Payload : Bytes; Status : out Outcome) is
      R : MC_FS.Root; Lock : MC_FS.File; Info : MC_FS.Entry_Info;
      Before, Pending : MC_Checkpoint.Descriptor; BH : Digest := Zero_Digest;
      DH : constant Digest := MC_SHA256.Hash (MC_Checkpoint.Encode (D));
      procedure Done is begin MC_FS.Close (Lock); MC_FS.Close (R); end Done;
   begin
      Status := Invalid_Input;
      if not MC_Checkpoint.Valid (D) or else D.Contract /= MC_Contract_Profile.Fingerprint
        or else D.Payload_Size /= Counter (Payload'Length) or else MC_SHA256.Hash (Payload) /= D.Payload
      then return; end if;
      MC_FS.Open_Root (Directory,R,Status,Private_Only => True); if Status /= OK then return; end if;
      MC_FS.Open_Locked (R,"checkpoint.lock",Lock,Status,
        Create_If_Missing => Expected=Zero_Digest and then D.Generation=1); if Status /= OK then Done; return; end if;
      MC_FS.Stat (R,"checkpoint-current.bin",Info,Status); if Status /= OK then Done; return; end if;
      if Info.Kind /= MC_FS.Absent then
         Read_Descriptor (R,"checkpoint-current.bin",Before,Status); if Status /= OK then Done; return; end if;
         BH := MC_SHA256.Hash (MC_Checkpoint.Encode (Before));
         Check_Anchor (Before,BH,Status); if Status /= OK then Done; return; end if;
         if Expected /= BH or else not MC_Checkpoint.Follows (Before,D,BH) then Status := Conflict; Done; return; end if;
      elsif Expected /= Zero_Digest or else D.Previous /= Zero_Digest or else D.Generation /= 1 then
         Status := Denied; Done; return;
      end if;
      MC_FS.Stat (R,"checkpoint-pending.bin",Info,Status); if Status /= OK then Done; return; end if;
      if Info.Kind /= MC_FS.Absent then
         Read_Descriptor (R,"checkpoint-pending.bin",Pending,Status); if Status /= OK then Done; return; end if;
         if MC_SHA256.Hash (MC_Checkpoint.Encode (Pending)) /= BH then Status := Conflict; Done; return; end if;
      end if;
      Validate_State (D,Payload,Status); if Status /= OK then Done; return; end if;
      Authorize ("checkpoint-stage",Before,D,Status); if Status /= OK then Done; return; end if;
      Keep (R,"snapshot-" & MC_Hex.Encode (D.Payload) & ".bin",Payload,Status);
      if Status /= OK then Done; return; end if;
      Keep (R,"checkpoint-" & MC_Hex.Encode (DH) & ".bin",MC_Checkpoint.Encode (D),Status);
      if Status /= OK then Done; return; end if;
      MC_Atomic.Write (R,"checkpoint-pending.bin",MC_Checkpoint.Encode (D),False,Status);
      if Status /= OK then Done; return; end if;
      Authorize ("checkpoint-anchor",Before,D,Status); if Status /= OK then Done; return; end if;
      Advance_Anchor (Expected,D,DH,Status); if Status /= OK then Done; return; end if;
      Check_Anchor (D,DH,Status); if Status /= OK then Status := Indeterminate; Done; return; end if;
      MC_Atomic.Write (R,"checkpoint-current.bin",MC_Checkpoint.Encode (D),False,Status);
      if Status /= OK then Status := Indeterminate; end if; Done;
   exception when others => Done; Status := Indeterminate;
   end Publish;
   procedure Reconcile (Directory : String; Root_ID, Stream_ID : Identity;
      Status : out Outcome) is
      R : MC_FS.Root; Lock : MC_FS.File; Info : MC_FS.Entry_Info;
      Before, Pending : MC_Checkpoint.Descriptor; B : Bytes (1..Max_Message); Used : Natural;
      PH, BH : Digest := Zero_Digest;
      procedure Done is begin MC_FS.Close (Lock); MC_FS.Close (R); end Done;
   begin
      MC_FS.Open_Root (Directory,R,Status,Private_Only => True); if Status /= OK then return; end if;
      MC_FS.Open_Locked (R,"checkpoint.lock",Lock,Status,Create_If_Missing=>False); if Status /= OK then Done; return; end if;
      Read_Descriptor (R,"checkpoint-pending.bin",Pending,Status); if Status /= OK then Done; return; end if;
      if Pending.Root_ID /= Root_ID or else Pending.Stream_ID /= Stream_ID then Status := Denied; Done; return; end if;
      PH := MC_SHA256.Hash (MC_Checkpoint.Encode (Pending));
      Check_Anchor (Pending,PH,Status); if Status /= OK then Done; return; end if;
      Read_Payload (R,Pending,B,Used,Status); if Status /= OK then Done; return; end if;
      MC_FS.Stat (R,"checkpoint-current.bin",Info,Status); if Status /= OK then Done; return; end if;
      if Info.Kind /= MC_FS.Absent then
         Read_Descriptor (R,"checkpoint-current.bin",Before,Status); if Status /= OK then Done; return; end if;
         BH := MC_SHA256.Hash (MC_Checkpoint.Encode (Before));
         if BH = PH then Status := OK; Done; return; end if;
         if not MC_Checkpoint.Follows (Before,Pending,BH) then Status := Conflict; Done; return; end if;
      elsif Pending.Generation /= 1 or else Pending.Previous /= Zero_Digest then Status := Conflict; Done; return;
      end if;
      Authorize ("checkpoint-reconcile",Before,Pending,Status); if Status /= OK then Done; return; end if;
      MC_Atomic.Write (R,"checkpoint-current.bin",MC_Checkpoint.Encode (Pending),False,Status); Done;
   exception when others => Done; Status := Indeterminate;
   end Reconcile;
end MC_Checkpoint_Store;
