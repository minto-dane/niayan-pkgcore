-- SPDX-License-Identifier: MIT
package body MC_Properties with SPARK_Mode is
   procedure Parse(Data : Bytes; D : out Document; Status : out Outcome) is
      Start : Positive:=Data'First; Split : Natural:=0;
   begin
      D:=(others=><>); Status:=Invalid_Input;
      if Data'Length=0 or else Data'Length>Maximum*4_160 then return; end if;
      for I in Data'Range loop
         if Data(I)=61 and then Split=0 then Split:=I;
         elsif Data(I)=10 then
            if Split=0 or else Split=Start or else I=Split+1 or else I-Start>4_159 or else D.Count=Maximum then return; end if;
            declare Key : String(1..Split-Start); Value : String(1..I-Split-1); begin
               for J in Key'Range loop Key(J):=Character'Val(Data(Start+J-1)); end loop;
               for J in Value'Range loop Value(J):=Character'Val(Data(Split+J)); end loop;
               if Key'Length>63 or else not MC_Text.Identifier(Key) then return; end if;
               for J in 1..D.Count loop if MC_Text.Image(D.Items(J).Key)=Key then return; end if; end loop;
               D.Count:=D.Count+1;
               MC_Text.Set(D.Items(D.Count).Key,Key,Status); if Status/=OK then return; end if;
               MC_Text.Set(D.Items(D.Count).Value,Value,Status); if Status/=OK then return; end if;
            end;
            Start:=I+1; Split:=0;
         elsif Data(I)<32 or else Data(I)>126 then return;
         end if;
      end loop;
      Status:=(if Start=Data'Last+1 and then D.Count>0 then OK else Invalid_Input);
   end;
   procedure Get(D : Document; Key : String; V : out MC_Text.Value; Status : out Outcome) is
   begin
      V:=MC_Text.Empty; Status:=Invalid_Input;
      for I in 1..D.Count loop
         if MC_Text.Image(D.Items(I).Key)=Key then V:=D.Items(I).Value; Status:=OK; return; end if;
      end loop;
   end;
   function Has_Exactly(D : Document; Keys : String) return Boolean is
      Start : Positive:=Keys'First; N : Natural:=0; V : MC_Text.Value; S : Outcome;
   begin
      for I in Keys'First..Keys'Last+1 loop
         if I=Keys'Last+1 or else Keys(I)=',' then
            if I=Start then return False; end if;
            Get(D,Keys(Start..I-1),V,S); if S/=OK then return False; end if;
            N:=N+1; Start:=I+1;
         end if;
      end loop;
      return N=D.Count;
   end;
end MC_Properties;
