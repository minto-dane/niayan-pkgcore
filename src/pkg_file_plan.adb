-- SPDX-License-Identifier: MIT
with MC_Codec; with MC_Paths;
package body Pkg_File_Plan with SPARK_Mode is
   use type MC_Types.Byte;
   use type Word; use type Wide;
   Magic : constant Bytes := (16#4D#,16#43#,16#50#,16#4C#,16#41#,16#4E#,16#30#,16#32#);
   function Valid(S : Shape) return Boolean is
   begin
      if S.Node_Kind=Absent then return S=(Absent,0,0,0,0,0,0,Zero_Digest,Zero_Digest); end if;
      if (S.Mode and not 8#777#)/=0 or else S.Xattrs=Zero_Digest then return False; end if;
      case S.Node_Kind is
         when Regular => return S.Content/=Zero_Digest and then S.Size<=8*1024*1024*1024;
         when Directory => return S.Content=Zero_Digest and then S.Size=0 and then S.Mtime_Sec=0
           and then S.Mtime_Nsec=0 and then (S.Mode and 8#022#)=0;
         when Symbolic_Link => return S.Content/=Zero_Digest and then S.Size in 1..4096
            and then S.Mode=8#777# and then S.Mtime_Sec=0 and then S.Mtime_Nsec=0;
         when Absent => return False;
      end case;
   end Valid;
   function Equal(A,B : Shape) return Boolean is (A=B);
   function Allowed_Path(Path : String) return Boolean is
      Start : Positive:=Path'First;
   begin
      if not MC_Paths.Safe_Relative(Path) then return False; end if;
      for J in Path'Range loop
         if Path(J)='/' then
            if Path(Start..J-1)=".mission" or else Path(Start..J-1)=".mc"
              or else (J-Start>=8 and then Path(Start..Start+7)=".mc-tmp-") then return False; end if;
            Start:=J+1;
         end if;
      end loop;
      if Path(Start..Path'Last)=".mission" or else Path(Start..Path'Last)=".mc"
        or else (Path'Last-Start+1>=8 and then Path(Start..Start+7)=".mc-tmp-") then return False; end if;
      -- Never package-manage kernel virtual filesystems, audit, secrets or our own
      -- independent trust/recovery state via a general file plan.
      if Path="proc" or else Path="sys" or else Path="dev" or else Path="run"
        or else Path="etc/shadow" or else Path="etc/gshadow"
        or else Path="var/lib/mission" or else Path="var/lib/nia"
        or else Path="etc/nia/keys" or else Path="var/log/nia"
        or else Path="var/log/audit"
        or else Path="etc/mission/keys" then return False; end if;
      for J in Path'Range loop
         if Path(J)='/' then
            if Path(Path'First..J-1)="proc" or else Path(Path'First..J-1)="sys"
              or else Path(Path'First..J-1)="dev" or else Path(Path'First..J-1)="run"
              or else Path(Path'First..J-1)="var/lib/mission"
              or else Path(Path'First..J-1)="var/lib/nia"
              or else Path(Path'First..J-1)="var/log/nia"
              or else Path(Path'First..J-1)="etc/nia/keys"
              or else Path(Path'First..J-1)="var/log/audit"
              or else Path(Path'First..J-1)="etc/mission/keys" then return False; end if;
         end if;
      end loop;
      return True;
   end Allowed_Path;
   function Ancestor(A,B : String) return Boolean is
     (A'Length<B'Length and then B(B'First..B'First+A'Length-1)=A
       and then B(B'First+A'Length)='/');
   function Layout_Valid(P : Plan) return Boolean is
   begin
      if P.Root_ID=Zero_Identity or else P.Transaction_ID=Zero_Identity or else P.Count=0
        or else P.Base_Generation=Counter'Last or else P.Target_Generation/=P.Base_Generation+1
        or else P.Epoch=0 or else P.Fence=0 or else P.Package_Set=Zero_Digest
        or else P.Effect_Contract=Zero_Digest then return False; end if;
      for I in 1..P.Count loop
         if not Allowed_Path(MC_Text.Image(P.Changes(I).Path))
           or else P.Changes(I).Domain not in Packaged_Files | Managed_Configuration
           or else not Valid(P.Changes(I).Before) or else not Valid(P.Changes(I).After)
           or else P.Changes(I).Before=P.Changes(I).After then return False; end if;
         -- Existing directories are not replaced or removed by this profile.
         -- This avoids deleting untracked data or making existing parent permissions
         -- transiently incompatible. Empty obsolete directories are harmless retained state.
         if P.Changes(I).Before.Node_Kind=Directory then return False; end if;
         if P.Changes(I).After.Node_Kind=Directory and then P.Changes(I).Before.Node_Kind/=Absent then return False; end if;
         for J in 1..P.Count loop
            if I/=J then
               if MC_Text.Equal(P.Changes(I).Path,P.Changes(J).Path) then return False; end if;
               if Ancestor(MC_Text.Image(P.Changes(I).Path),MC_Text.Image(P.Changes(J).Path)) then
                  if P.Changes(I).After.Node_Kind/=Directory or else I>=J
                    or else P.Changes(J).Before.Node_Kind/=Absent then return False; end if;
               end if;
            end if;
         end loop;
      end loop;
      return True;
   end Layout_Valid;
   function Encode(S : Shape) return Encoded_Shape is
      B : Encoded_Shape:=(others=>0);
   begin
      B(1):=Byte(Kind'Pos(S.Node_Kind)); MC_Codec.Put32(B,5,S.Mode);
      MC_Codec.Put32(B,9,S.UID); MC_Codec.Put32(B,13,S.GID);
      MC_Codec.Put64(B,17,Wide(S.Size)); MC_Codec.Put64(B,25,Wide(S.Mtime_Sec));
      MC_Codec.Put32(B,33,Word(S.Mtime_Nsec)); B(41..72):=S.Content; B(73..104):=S.Xattrs;
      return B;
   end Encode;
   procedure Decode_Shape(B : Bytes; S : out Shape; Status : out Outcome) is
   begin
      S:=(others=><>); Status:=Invalid_Input;
      if B'First/=1 or else B'Length/=Shape_Size or else Natural(B(1))>Kind'Pos(Kind'Last) then return; end if;
      for J in 2..4 loop if B(J)/=0 then return; end if; end loop;
      for J in 37..40 loop if B(J)/=0 then return; end if; end loop;
      for J in 105..128 loop if B(J)/=0 then return; end if; end loop;
      if MC_Codec.U64(B,17)>Wide(Counter'Last) or else MC_Codec.U64(B,25)>Wide(Counter'Last)
        or else MC_Codec.U32(B,33)>999_999_999 then return; end if;
      S.Node_Kind:=Kind'Val(B(1)); S.Mode:=MC_Codec.U32(B,5); S.UID:=MC_Codec.U32(B,9); S.GID:=MC_Codec.U32(B,13);
      S.Size:=Counter(MC_Codec.U64(B,17)); S.Mtime_Sec:=Counter(MC_Codec.U64(B,25));
      S.Mtime_Nsec:=Natural(MC_Codec.U32(B,33)); S.Content:=B(41..72); S.Xattrs:=B(73..104);
      if Valid(S) then Status:=OK; end if;
   end Decode_Shape;
   procedure Encode(P : Plan; B : out Bytes; Used : out Natural; Status : out Outcome) is
      Pos : Natural:=Header_Size; L : Natural;
   begin
      B:=(others=>0); Used:=0; Status:=Invalid_Input;
      if B'First/=1 or else B'Length<Header_Size or else not Layout_Valid(P) then return; end if;
      B(1..8):=Magic; B(9..24):=P.Root_ID; B(25..40):=P.Transaction_ID;
      MC_Codec.Put64(B,41,Wide(P.Base_Generation)); MC_Codec.Put64(B,49,Wide(P.Target_Generation));
      MC_Codec.Put64(B,57,Wide(P.Epoch)); MC_Codec.Put64(B,65,Wide(P.Fence));
      B(73..104):=P.Package_Set; B(105..136):=P.Effect_Contract; MC_Codec.Put32(B,137,Word(P.Count));
      for I in 1..P.Count loop
         L:=MC_Text.Length(P.Changes(I).Path);
         if B'Length-Pos<4+L+2*Shape_Size then Status:=Exhausted; return; end if;
         MC_Codec.Put16(B,Pos+1,L); B(Pos+3):=Byte(State_Domain'Pos(P.Changes(I).Domain)); Pos:=Pos+4;
         declare S : constant String:=MC_Text.Image(P.Changes(I).Path); begin
            for C of S loop Pos:=Pos+1; B(Pos):=Byte(Character'Pos(C)); end loop;
         end;
         B(Pos+1..Pos+Shape_Size):=Encode(P.Changes(I).Before); Pos:=Pos+Shape_Size;
         B(Pos+1..Pos+Shape_Size):=Encode(P.Changes(I).After); Pos:=Pos+Shape_Size;
      end loop;
      Used:=Pos; Status:=OK;
   end Encode;
   procedure Clear(P : out Plan) is
   begin
      P.Root_ID:=Zero_Identity; P.Transaction_ID:=Zero_Identity;
      P.Base_Generation:=0; P.Target_Generation:=0; P.Epoch:=0; P.Fence:=0;
      P.Package_Set:=Zero_Digest; P.Effect_Contract:=Zero_Digest; P.Count:=0;
      for I in P.Changes'Range loop P.Changes(I):=(others=><>); end loop;
   end Clear;
   procedure Decode(B : Bytes; P : out Plan; Status : out Outcome) is
      Pos : Natural:=Header_Size; L : Natural; S : Encoded_Shape; Field_Status : Outcome;
      type Offsets is array(1..4) of Positive;
      Checks : constant Offsets:=(41,49,57,65);
   begin
      Clear(P); Status:=Invalid_Input;
      if B'First/=1 or else B'Length<Header_Size or else B'Length>Max_Plan_Bytes or else B(1..8)/=Magic then return; end if;
      for J in 141..Header_Size loop if B(J)/=0 then return; end if; end loop;
      for O of Checks loop if MC_Codec.U64(B,O)>Wide(Counter'Last) then return; end if; end loop;
      if MC_Codec.U32(B,137)>Max_Changes then return; end if;
      P.Root_ID:=B(9..24); P.Transaction_ID:=B(25..40); P.Base_Generation:=Counter(MC_Codec.U64(B,41));
      P.Target_Generation:=Counter(MC_Codec.U64(B,49)); P.Epoch:=Counter(MC_Codec.U64(B,57));
      P.Fence:=Counter(MC_Codec.U64(B,65)); P.Package_Set:=B(73..104); P.Effect_Contract:=B(105..136);
      P.Count:=Natural(MC_Codec.U32(B,137));
      for I in 1..P.Count loop
         if B'Length-Pos<4 then return; end if;
         L:=MC_Codec.U16(B,Pos+1);
         if L=0 or else L>MC_Text.Max_Length or else Natural(B(Pos+3))>State_Domain'Pos(State_Domain'Last)
            or else B(Pos+4)/=0 then return; end if;
         P.Changes(I).Domain:=State_Domain'Val(B(Pos+3)); Pos:=Pos+4;
         if B'Length-Pos<L+2*Shape_Size then return; end if;
         declare Text_Length : constant Natural := L; Name : String(1..Text_Length); begin
            for J in Name'Range loop Name(J):=Character'Val(B(Pos+J)); end loop;
            MC_Text.Set(P.Changes(I).Path,Name,Field_Status); if Field_Status/=OK then return; end if;
         end;
         Pos:=Pos+L; S:=B(Pos+1..Pos+Shape_Size); Decode_Shape(S,P.Changes(I).Before,Field_Status);
         if Field_Status/=OK then return; end if; Pos:=Pos+Shape_Size;
         S:=B(Pos+1..Pos+Shape_Size); Decode_Shape(S,P.Changes(I).After,Field_Status);
         if Field_Status/=OK then return; end if; Pos:=Pos+Shape_Size;
      end loop;
      Status:=Invalid_Input;
      if Pos=B'Length and then Layout_Valid(P) then Status:=OK; end if;
   end Decode;
end Pkg_File_Plan;
