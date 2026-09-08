-- SPDX-License-Identifier: MIT
with MC_Codec;
package body Pkg_RPM_Fields with SPARK_Mode is
   use type MC_Types.Byte;
   function Count(M : Pkg_RPM.Metadata; Tag : Word) return Natural is
      I : constant Natural:=Pkg_RPM.Find(M,Tag);
   begin return (if I=0 then 0 else M.Entries(I).Item_Count); end;
   procedure Text(B : Bytes; M : Pkg_RPM.Metadata; Tag : Word; Item : Positive;
                  Value : out MC_Text.Value; Status : out Outcome) is
      I : constant Natural:=Pkg_RPM.Find(M,Tag); Start, End_Pos, N : Natural;
   begin
      Value:=MC_Text.Empty; Status:=Invalid_Input;
      if I=0 or else Item>M.Entries(I).Item_Count or else M.Entries(I).Data_Type not in 6|8|9 then return; end if;
      Start:=M.Entries(I).Data_Offset+1; End_Pos:=M.Entries(I).Data_Offset+M.Entries(I).Span; N:=1;
      if B'First/=1 or else End_Pos>B'Last then return; end if;
      for J in Start..End_Pos loop
         if B(J)=0 then
            if N=Item then
               if J-Start>MC_Text.Max_Length then Status:=Exhausted; return; end if;
               declare Text_Length : constant Natural := J-Start; S : String(1..Text_Length); begin
                  for K in S'Range loop S(K):=Character'Val(B(Start+K-1)); end loop;
                  MC_Text.Set(Value,S,Status); return;
               end;
            end if;
            N:=N+1; Start:=J+1;
         end if;
      end loop;
   end;
   procedure Number(B : Bytes; M : Pkg_RPM.Metadata; Tag : Word; Item : Positive;
                    Value : out Wide; Status : out Outcome) is
      I : constant Natural:=Pkg_RPM.Find(M,Tag); P, Width : Natural;
   begin
      Value:=0; Status:=Invalid_Input;
      if I=0 or else Item>M.Entries(I).Item_Count or else B'First/=1 then return; end if;
      case M.Entries(I).Data_Type is
         when 2 => Width:=1; when 3 => Width:=2; when 4 => Width:=4; when 5 => Width:=8;
         when others => return;
      end case;
      P:=M.Entries(I).Data_Offset+(Item-1)*Width+1;
      if P>B'Last or else B'Last-P+1<Width then return; end if;
      case Width is
         when 1 => Value:=Wide(B(P)); when 2 => Value:=Wide(MC_Codec.U16(B,P));
         when 4 => Value:=Wide(MC_Codec.U32(B,P)); when 8 => Value:=MC_Codec.U64(B,P);
         when others => return;
      end case;
      Status:=OK;
   end;
end Pkg_RPM_Fields;
