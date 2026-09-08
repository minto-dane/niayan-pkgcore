-- SPDX-License-Identifier: MIT
with MC_Codec; with MC_SHA256;
package body Pkg_Inventory with SPARK_Mode is
   use type Pkg_File_Plan.Kind; use type Pkg_File_Plan.State_Domain;
   use type Byte; use type Wide; use type Word;
   Magic : constant String:="MCINV001";
   function Under(Path,Prefix : String) return Boolean is
     (Path'Length>Prefix'Length and then Path(Path'First..Path'First+Prefix'Length-1)=Prefix
       and then Path(Path'First+Prefix'Length)='/');
   function Automatic_Path(Path : String) return Boolean is
     (Pkg_File_Plan.Allowed_Path(Path) and then (Under(Path,"usr") or else Under(Path,"opt"))
      and then not Under(Path,"usr/lib/modules") and then not Under(Path,"usr/lib/firmware")
      and then not Under(Path,"usr/lib/systemd") and then not Under(Path,"usr/lib/sysusers.d")
      and then not Under(Path,"usr/lib/tmpfiles.d") and then not Under(Path,"usr/lib/security")
      and then not Under(Path,"usr/lib64/security") and then not Under(Path,"usr/share/pki")
      and then not Under(Path,"usr/share/keys"));
   function Valid(M : Manifest) return Boolean is
   begin
      if M.Root_ID=Zero_Identity or else M.Package_Set=Zero_Digest or else M.Contract=Zero_Digest
        or else M.Count=0 then return False; end if;
      for I in 1..M.Count loop
         if not Pkg_File_Plan.Allowed_Path(MC_Text.Image(M.Items(I).Path))
           or else not Pkg_File_Plan.Valid(M.Items(I).Desired)
           or else M.Items(I).Desired.Node_Kind=Pkg_File_Plan.Absent then return False; end if;
         if I>1 and then MC_Text.Image(M.Items(I-1).Path)>=MC_Text.Image(M.Items(I).Path) then return False; end if;
         if M.Items(I).Allow_Automatic_Repair and then
           (not Automatic_Path(MC_Text.Image(M.Items(I).Path))
             or else M.Items(I).Domain/=Pkg_File_Plan.Packaged_Files or else M.Items(I).Boot_Or_Security_Critical
             or else M.Items(I).Desired.Node_Kind/=Pkg_File_Plan.Regular) then return False; end if;
      end loop;
      return True;
   end Valid;
   function Fingerprint(M : Manifest) return Digest is
      C : MC_SHA256.Context:=MC_SHA256.Initialize;
      Header : Bytes(1..128):=(others=>0); Prefix : Bytes(1..136); Inner : Digest;
   begin
      for I in Magic'Range loop Header(I):=Byte(Character'Pos(Magic(I))); end loop;
      Header(9..24):=M.Root_ID; MC_Codec.Put64(Header,25,Wide(M.Generation));
      Header(33..64):=M.Package_Set; Header(65..96):=M.Contract;
      MC_Codec.Put32(Header,97,Word(M.Count)); MC_SHA256.Update(C,Header);
      for I in 1..M.Count loop
         Prefix:=(others=>0); MC_Codec.Put32(Prefix,1,Word(MC_Text.Length(M.Items(I).Path)));
         Prefix(5):=Byte(Pkg_File_Plan.State_Domain'Pos(M.Items(I).Domain));
         Prefix(6):=Boolean'Pos(M.Items(I).Allow_Automatic_Repair);
         Prefix(7):=Boolean'Pos(M.Items(I).Boot_Or_Security_Critical);
         Prefix(9..136):=Pkg_File_Plan.Encode(M.Items(I).Desired); MC_SHA256.Update(C,Prefix);
         declare Text : constant String:=MC_Text.Image(M.Items(I).Path); Data : Bytes(1..Text'Length) := (others => 0); begin
            for J in Text'Range loop Data(J):=Byte(Character'Pos(Text(J))); end loop;
            MC_SHA256.Update(C,Data);
         end;
      end loop;
      Inner:=MC_SHA256.Finish(C); MC_SHA256.Update(C,Inner); return MC_SHA256.Finish(C);
   end Fingerprint;
   procedure Encode(M : Manifest; B : out Bytes; Used : out Natural; Status : out Outcome) is
      Need : Natural:=128+32; Pos : Natural; L : Natural;
   begin
      B:=(others=>0); Used:=0; Status:=Invalid_Input;
      if not Valid(M) then return; end if;
      for I in 1..M.Count loop Need:=Need+136+MC_Text.Length(M.Items(I).Path); end loop;
      if Need>B'Length or else Need>Maximum_Encoding then Status:=Exhausted; return; end if;
      for I in Magic'Range loop B(B'First+I-1):=Byte(Character'Pos(Magic(I))); end loop;
      B(B'First+8..B'First+23):=M.Root_ID;
      MC_Codec.Put64(B,B'First+24,Wide(M.Generation));
      B(B'First+32..B'First+63):=M.Package_Set; B(B'First+64..B'First+95):=M.Contract;
      MC_Codec.Put32(B,B'First+96,Word(M.Count)); Pos:=B'First+128;
      for I in 1..M.Count loop
         L:=MC_Text.Length(M.Items(I).Path); MC_Codec.Put32(B,Pos,Word(L));
         B(Pos+4):=Byte(Pkg_File_Plan.State_Domain'Pos(M.Items(I).Domain));
         B(Pos+5):=Boolean'Pos(M.Items(I).Allow_Automatic_Repair);
         B(Pos+6):=Boolean'Pos(M.Items(I).Boot_Or_Security_Critical);
         B(Pos+8..Pos+135):=Pkg_File_Plan.Encode(M.Items(I).Desired);
         declare S : constant String:=MC_Text.Image(M.Items(I).Path); begin
            for J in S'Range loop B(Pos+135+J):=Byte(Character'Pos(S(J))); end loop;
         end;
         Pos:=Pos+136+L;
      end loop;
      B(Pos..Pos+31):=MC_SHA256.Hash(B(B'First..Pos-1)); Used:=Need; Status:=OK;
   end Encode;
   procedure Decode(B : Bytes; M : out Manifest; Status : out Outcome) is
      Pos : Natural; N,L : Counter; S : Outcome; Text : String(1..MC_Text.Max_Length) := (others => ' ');
      function Zeros(A,Z : Natural) return Boolean is
      begin for I in A..Z loop if B(I)/=0 then return False; end if; end loop; return True; end;
   begin
      M:=(others=><>); Status:=Invalid_Input;
      if B'Length<160 or else B'Length>Maximum_Encoding then return; end if;
      for I in Magic'Range loop if B(B'First+I-1)/=Byte(Character'Pos(Magic(I))) then return; end if; end loop;
      if B(B'Last-31..B'Last)/=MC_SHA256.Hash(B(B'First..B'Last-32)) then Status:=Corrupt; return; end if;
      if not Zeros(B'First+100,B'First+127) then return; end if;
      M.Root_ID:=B(B'First+8..B'First+23);
      declare Generation : constant Wide := MC_Codec.U64(B,B'First+24); begin
         if Generation > Wide(Counter'Last) then return; end if;
         M.Generation:=Counter(Generation);
      end;
      M.Package_Set:=B(B'First+32..B'First+63); M.Contract:=B(B'First+64..B'First+95);
      N:=Counter(MC_Codec.U32(B,B'First+96)); if N=0 or else N>Max_Entries then return; end if;
      M.Count:=Natural(N); Pos:=B'First+128;
      for I in 1..M.Count loop
         if Pos>B'Last-31 or else B'Last-31-Pos<136 then return; end if;
         L:=Counter(MC_Codec.U32(B,Pos));
         if L=0 or else L>MC_Text.Max_Length
           or else L>Counter(B'Last-31-Pos-136) then return; end if;
         if B(Pos+4)>Pkg_File_Plan.State_Domain'Pos(Pkg_File_Plan.State_Domain'Last)
           or else B(Pos+5)>1 or else B(Pos+6)>1 or else B(Pos+7)/=0 then return; end if;
         M.Items(I).Domain:=Pkg_File_Plan.State_Domain'Val(B(Pos+4));
         M.Items(I).Allow_Automatic_Repair:=B(Pos+5)=1; M.Items(I).Boot_Or_Security_Critical:=B(Pos+6)=1;
         declare Shape_Data : constant Pkg_File_Plan.Encoded_Shape:=B(Pos+8..Pos+135); begin
            Pkg_File_Plan.Decode_Shape(Shape_Data,M.Items(I).Desired,S);
         end;
         if S/=OK then return; end if;
         -- Reject noncanonical shape padding by a semantic round trip.
         if Pkg_File_Plan.Encode(M.Items(I).Desired)/=B(Pos+8..Pos+135) then return; end if;
         for J in 1..Natural(L) loop Text(J):=Character'Val(B(Pos+135+J)); end loop;
         MC_Text.Set(M.Items(I).Path,Text(1..Natural(L)),S); if S/=OK then return; end if;
         Pos:=Pos+136+Natural(L);
      end loop;
      if Pos/=B'Last-31 or else not Valid(M) then return; end if;
      Status:=OK;
   end Decode;
end Pkg_Inventory;
