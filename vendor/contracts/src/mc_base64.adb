-- SPDX-License-Identifier: MIT
package body MC_Base64 with SPARK_Mode is
   Alphabet : constant String:="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
   function Encode(Data : Bytes) return String is
      R : String(1..4*((Data'Length+2)/3)) := (others=>'='); I : Natural:=0; P : Positive:=1; A,B,C : Natural;
   begin
      while I<Data'Length loop
         pragma Loop_Variant(Increases=>I);
         A:=Natural(Data(Data'First+I)); B:=0; C:=0;
         if I+1<Data'Length then B:=Natural(Data(Data'First+I+1)); end if;
         if I+2<Data'Length then C:=Natural(Data(Data'First+I+2)); end if;
         R(P):=Alphabet(A/4+1); R(P+1):=Alphabet((A mod 4)*16+B/16+1);
         R(P+2):=(if I+1<Data'Length then Alphabet((B mod 16)*4+C/64+1) else '=');
         R(P+3):=(if I+2<Data'Length then Alphabet(C mod 64+1) else '=');
         I:=I+3; P:=P+4;
      end loop; return R;
   end;
   procedure Decode(Text : String; Data : out Bytes; Used : out Natural; Status : out Outcome) is
      Pos : Natural:=0; V : array(0..3) of Natural := (others=>0); Pads : Natural;
      function Value(C : Character) return Natural is
      begin for I in Alphabet'Range loop if Alphabet(I)=C then return I-1; end if; end loop; return 64; end;
      procedure Emit(N : Natural) is begin Used:=Used+1; Data(Data'First+Used-1):=Byte(N); end;
   begin
      Used:=0; Data:=(others=>0); Status:=Invalid_Input;
      if Text'Length mod 4/=0 or else Text'Length>1_398_104 then return; end if;
      while Pos<Text'Length loop
         Pads:=0;
         for I in 0..3 loop
            if Text(Text'First+Pos+I)='=' then V(I):=0; Pads:=Pads+1;
            else
               if Pads>0 then return; end if;
               V(I):=Value(Text(Text'First+Pos+I)); if V(I)=64 then return; end if;
            end if;
         end loop;
         if Pads>2 or else (Pads>0 and then Pos+4/=Text'Length) or else Used+3-Pads>Data'Length then return; end if;
         if Pads=2 and then V(1) mod 16/=0 then return; end if;
         if Pads=1 and then V(2) mod 4/=0 then return; end if;
         Emit(V(0)*4+V(1)/16);
         if Pads<2 then Emit((V(1) mod 16)*16+V(2)/4); end if;
         if Pads=0 then Emit((V(2) mod 4)*64+V(3)); end if;
         Pos:=Pos+4;
      end loop; Status:=OK;
   end;
end MC_Base64;
