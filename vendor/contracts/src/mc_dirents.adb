-- SPDX-License-Identifier: MIT
package body MC_Dirents with SPARK_Mode is
   use type Byte;
   function Image(N : Name) return String is (N.Data(1..N.Length));
   procedure Append_Linux64_LE (Data : Bytes; L : in out Listing; Status : out Outcome) is
      W : Listing:=L;P : Natural:=Data'First;Len,Ending : Natural;N : Name;
   begin
      Status:=Corrupt;
      while P<=Data'Last loop
         if Data'Last-P<19 then return;end if;
         Len:=Natural(Data(P+16))+Natural(Data(P+17))*256;
         if Len<20 or else Len>Data'Last-P+1 then return;end if;
         Ending:=P+19;
         while Ending<P+Len and then Data(Ending)/=0 loop Ending:=Ending+1;end loop;
         if Ending=P+Len or else Ending=P+19 or else Ending-(P+19)>255 then return;end if;
         N:=(others=><>);N.Length:=Ending-(P+19);
         for J in 1..N.Length loop
            if Data(P+18+J)=47 then return;end if;
            N.Data(J):=Character'Val(Data(P+18+J));
         end loop;
         if Image(N)/="." and then Image(N)/=".." then
            for J in 1..W.Count loop if Image(W.Names(J))=Image(N) then return;end if;end loop;
            if W.Count=Max_Names then Status:=Exhausted;return;end if;
            W.Count:=W.Count+1;W.Names(W.Count):=N;
         end if;
         P:=P+Len;
      end loop;
      L:=W;Status:=OK;
   end Append_Linux64_LE;
   procedure Sort(L : in out Listing) is N : Name;J : Natural;
   begin
      for I in 2..L.Count loop
         N:=L.Names(I);J:=I;
         while J>1 and then Image(N)<Image(L.Names(J-1)) loop L.Names(J):=L.Names(J-1);J:=J-1;end loop;
         L.Names(J):=N;
      end loop;
   end Sort;
end MC_Dirents;
