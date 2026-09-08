-- SPDX-License-Identifier: MIT
with MC_Numbers;
package body MC_JSON with SPARK_Mode is
   use type MC_Types.Byte;
   procedure String_Bytes(Data : Bytes; D : Document; N : Index; Value : out Bytes; Used : out Natural; Status : out Outcome) is
      I : Natural; B : Byte;
   begin
      Used:=0; Value:=(others=>0); Status:=Invalid_Input;
      if N=0 or else N>D.Count or else D.Nodes(N).Node_Kind/=String_Node or else D.Nodes(N).First<Data'First
        or else D.Nodes(N).Last>Data'Last or else D.Nodes(N).Last<=D.Nodes(N).First then return; end if;
      I:=D.Nodes(N).First+1;
      while I<D.Nodes(N).Last loop
         pragma Loop_Variant(Increases=>I);
         B:=Data(I); I:=I+1;
         if B=92 then
            if I>=D.Nodes(N).Last then return; end if;
            case Data(I) is
               when 34|92|47=>B:=Data(I);
               when 98=>B:=8; when 102=>B:=12; when 110=>B:=10; when 114=>B:=13; when 116=>B:=9;
               when others=>return;
            end case; I:=I+1;
         end if;
         if Used=Value'Length then Status:=Exhausted; return; end if;
         Used:=Used+1; Value(Value'First+Used-1):=B;
      end loop; Status:=OK;
   end;
   function Member(Data : Bytes; D : Document; Object_Index : Index; Key : String) return Index is
      I : Natural range 0..Maximum_Nodes+1; B : Bytes(1..256); Used : Natural; S : Outcome; Equal : Boolean;
   begin
      if Object_Index=0 or else Object_Index>D.Count or else D.Nodes(Object_Index).Node_Kind/=Object_Node then return 0; end if;
      if D.Nodes(Object_Index).End_Index>D.Count then return 0; end if;
      I:=Natural(Object_Index)+1;
      while I<=D.Nodes(Object_Index).End_Index loop
         pragma Loop_Variant(Increases=>I);
         String_Bytes(Data,D,I,B,Used,S); if S/=OK then return 0; end if;
         Equal:=Used=Key'Length;
         if Equal then for J in Key'Range loop if B(J-Key'First+1)/=Byte(Character'Pos(Key(J))) then Equal:=False; end if; end loop; end if;
         if Equal then return I+1; end if;
         if I+1>D.Count or else D.Nodes(I+1).End_Index<I+1 then return 0; end if;
         I:=Natural(D.Nodes(I+1).End_Index)+1;
      end loop; return 0;
   end;
   function Element(D : Document; Array_Index : Index; Position : Positive) return Index is
      I : Natural range 0..Maximum_Nodes+1; P : Positive:=1;
   begin
      if Array_Index=0 or else Array_Index>D.Count or else D.Nodes(Array_Index).Node_Kind/=Array_Node then return 0; end if;
      if D.Nodes(Array_Index).End_Index>D.Count then return 0; end if;
      I:=Natural(Array_Index)+1;
      while I<=D.Nodes(Array_Index).End_Index loop
         pragma Loop_Variant(Increases=>I);
         if P=Position then return I; end if; if D.Nodes(I).End_Index<I then return 0; end if;
         I:=Natural(D.Nodes(I).End_Index)+1; P:=P+1;
      end loop; return 0;
   end;
   procedure Parse(Data : Bytes; D : out Document; Status : out Outcome) is
      Pos : Natural:=Data'First; Bad : Boolean:=False;
      procedure Space is begin while Pos<=Data'Last and then Data(Pos) in 9|10|13|32 loop Pos:=Pos+1; end loop; end;
      procedure Add(K : Kind; Parent : Index; N : out Index) is
      begin
         N:=0; if D.Count=Maximum_Nodes then Bad:=True; return; end if;
         D.Count:=D.Count+1; N:=D.Count; D.Nodes(N):=(K,Pos,Pos,Parent,N);
      end;
      procedure String_Node_Read(Parent : Index; N : out Index) is
         Escaped : Boolean:=False;
      begin
         Add(String_Node,Parent,N); if Bad then return; end if;
         if Pos>Data'Last or else Data(Pos)/=34 then Bad:=True; return; end if; Pos:=Pos+1;
         while Pos<=Data'Last loop
            if Escaped then
               if Data(Pos) not in 34|92|47|98|102|110|114|116 then Bad:=True; return; end if;
               Escaped:=False;
            elsif Data(Pos)=92 then Escaped:=True;
            elsif Data(Pos)=34 then D.Nodes(N).Last:=Pos; Pos:=Pos+1; return;
            elsif Data(Pos)<32 or else Data(Pos)>126 then Bad:=True; return; end if;
            Pos:=Pos+1;
         end loop; Bad:=True;
      end;
      procedure Value_Read(Parent : Index; Depth : Natural; N : out Index);
      procedure Value_Read(Parent : Index; Depth : Natural; N : out Index) is
         K,Value_Node : Index; Earlier : Natural range 0..Maximum_Nodes+1; Object_Form : Boolean; Close_Byte : Byte;
         Key,Other : Bytes(1..256); KN,ON : Natural; S : Outcome;
      begin
         N:=0; Space;
         if Depth>24 or else Pos>Data'Last then Bad:=True; return; end if;
         if Data(Pos)=34 then String_Node_Read(Parent,N); return;
         elsif Data(Pos) in 123|91 then
            Object_Form:=Data(Pos)=123; Close_Byte:=(if Object_Form then 125 else 93);
            Add((if Object_Form then Object_Node else Array_Node),Parent,N); if Bad then return; end if;
            Pos:=Pos+1; Space;
            if Pos<=Data'Last and then Data(Pos)=Close_Byte then D.Nodes(N).Last:=Pos; Pos:=Pos+1; return; end if;
            loop
               if Object_Form then
                  String_Node_Read(N,K); if Bad then return; end if;
                  String_Bytes(Data,D,K,Key,KN,S); if S/=OK then Bad:=True; return; end if;
                  Earlier:=N+1;
                  while Earlier<K loop
                     String_Bytes(Data,D,Earlier,Other,ON,S);
                     if S/=OK or else (KN=ON and then Key(1..KN)=Other(1..ON)) then Bad:=True; return; end if;
                     Earlier:=Natural(D.Nodes(Earlier+1).End_Index)+1;
                  end loop;
                  Space; if Pos>Data'Last or else Data(Pos)/=58 then Bad:=True; return; end if; Pos:=Pos+1;
               end if;
               Value_Read(N,Depth+1,Value_Node); if Bad or else Value_Node=0 then Bad:=True; return; end if;
               Space; if Pos>Data'Last then Bad:=True; return; end if;
               if Data(Pos)=Close_Byte then D.Nodes(N).Last:=Pos; D.Nodes(N).End_Index:=D.Count; Pos:=Pos+1; return;
               elsif Data(Pos)/=44 then Bad:=True; return;
               else Pos:=Pos+1; Space; end if;
            end loop;
         elsif Data(Pos) in 48..57 then
            Add(Number_Node,Parent,N); if Bad then return; end if;
            while Pos<=Data'Last and then Data(Pos) in 48..57 loop Pos:=Pos+1; end loop;
            D.Nodes(N).Last:=Pos-1;
            if Pos-D.Nodes(N).First>20 or else (Pos-D.Nodes(N).First>1 and then Data(D.Nodes(N).First)=48) then Bad:=True; end if;
         else
            declare Literal : constant String:=(if Data(Pos)=116 then "true" elsif Data(Pos)=102 then "false" else "null");
               Knd : constant Kind:=(if Data(Pos)=116 then True_Node elsif Data(Pos)=102 then False_Node else Null_Node);
            begin
               Add(Knd,Parent,N); if Bad then return; end if;
               if Literal'Length>Data'Last-Pos+1 then Bad:=True; return; end if;
               for C of Literal loop if Data(Pos)/=Byte(Character'Pos(C)) then Bad:=True; return; end if; Pos:=Pos+1; end loop;
               D.Nodes(N).Last:=Pos-1;
            end;
         end if;
      end;
      N : Index;
   begin
      D:=(others=><>); Status:=Invalid_Input; if Data'Length=0 or else Data'Length>262_144 then return; end if;
      Value_Read(0,0,N); Space;
      if not Bad and then Pos=Data'Last+1 and then N=1 then Status:=OK; end if;
   end;
   procedure Natural_Number(Data : Bytes; D : Document; N : Index; Value : out Counter; Status : out Outcome) is
      B : Bytes(1..20) := (others=>0); Used : Natural;
   begin
      Value:=0; Status:=Invalid_Input;
      if N=0 or else N>D.Count then return; end if;
      if D.Nodes(N).Node_Kind=String_Node then String_Bytes(Data,D,N,B,Used,Status); if Status/=OK then return; end if;
      elsif D.Nodes(N).Node_Kind=Number_Node then
         Used:=D.Nodes(N).Last-D.Nodes(N).First+1; if Used>20 then return; end if;
         B(1..Used):=Data(D.Nodes(N).First..D.Nodes(N).Last);
      else return; end if;
      declare Length : constant Natural := Used; S : String(1..Length); begin
         for I in S'Range loop S(I):=Character'Val(B(I)); end loop; MC_Numbers.Parse(S,Value,Status);
      end;
   end;
end MC_JSON;
