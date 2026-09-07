-- SPDX-License-Identifier: MIT
with Interfaces.C; with Interfaces.C.Strings; with System;
with MC_FS; with MC_Text; with MC_Clock; with Pkg_File_Plan;
package body Pkg_Archive with SPARK_Mode => Off is
   use Interfaces.C; use Interfaces.C.Strings; use type System.Address;
   use type Pkg_File_Plan.Kind; use type Word;
   function New_Archive return System.Address with Import,Convention=>C,External_Name=>"archive_read_new";
   function Filter_RPM(A : System.Address) return int with Import,Convention=>C,External_Name=>"archive_read_support_filter_rpm";
   function Filter_Gzip(A : System.Address) return int with Import,Convention=>C,External_Name=>"archive_read_support_filter_gzip";
   function Filter_XZ(A : System.Address) return int with Import,Convention=>C,External_Name=>"archive_read_support_filter_xz";
   function Filter_Zstd(A : System.Address) return int with Import,Convention=>C,External_Name=>"archive_read_support_filter_zstd";
   function Filter_Bzip2(A : System.Address) return int with Import,Convention=>C,External_Name=>"archive_read_support_filter_bzip2";
   function Format_CPIO(A : System.Address) return int with Import,Convention=>C,External_Name=>"archive_read_support_format_cpio";
   function Open_FD(A : System.Address; FD : int; Block_Size : size_t) return int with Import,Convention=>C,External_Name=>"archive_read_open_fd";
   function Next_Header(A : System.Address; E : access System.Address) return int with Import,Convention=>C,External_Name=>"archive_read_next_header";
   function Read_Data(A,B : System.Address; Size : size_t) return long with Import,Convention=>C,External_Name=>"archive_read_data";
   function Free_Archive(A : System.Address) return int with Import,Convention=>C,External_Name=>"archive_read_free";
   function Pathname(E : System.Address) return chars_ptr with Import,Convention=>C,External_Name=>"archive_entry_pathname";
   function Symlink(E : System.Address) return chars_ptr with Import,Convention=>C,External_Name=>"archive_entry_symlink";
   function Hardlink(E : System.Address) return chars_ptr with Import,Convention=>C,External_Name=>"archive_entry_hardlink";
   function Mode(E : System.Address) return unsigned with Import,Convention=>C,External_Name=>"archive_entry_mode";
   function Size(E : System.Address) return long_long with Import,Convention=>C,External_Name=>"archive_entry_size";
   function Sparse_Count(E : System.Address) return int with Import,Convention=>C,External_Name=>"archive_entry_sparse_count";
   function Bounded(P : chars_ptr) return String is
      function Strnlen(P : chars_ptr; N : size_t) return size_t with Import,Convention=>C,External_Name=>"strnlen";
      N : size_t;
   begin
      if P=Null_Ptr then return ""; end if;
      N:=Strnlen(P,4097); if N>4096 then return ""; end if;
      return Value(P,N);
   end;
   procedure Stage(S : in out MC_Store.Store; RPM : Digest; Map : Pkg_Payload_Map.Inventory;
                   Deadline : Counter; Status : out Outcome) is
      A : System.Address:=System.Null_Address; E : aliased System.Address:=System.Null_Address;
      F : MC_FS.File; W : MC_Store.Writer; RC, Ignored : int; N : long;
      Seen : array(1..Pkg_Payload_Map.Capacity) of Boolean:=(others=>False);
      B : Bytes(1..65_536); Index : Natural; Now, Total : Counter:=0; D : Digest;
      pragma Unreferenced(Ignored);
      procedure Cleanup is begin MC_Store.Abort_Write(W); MC_FS.Close(F); if A/=System.Null_Address then Ignored:=Free_Archive(A); A:=System.Null_Address; end if; end;
   begin
      MC_Store.Open_Object(S,RPM,F,Status); if Status/=OK then return; end if;
      A:=New_Archive;
      if A=System.Null_Address then Status:=Exhausted; Cleanup; return; end if;
      if Filter_RPM(A)/=0 or else Filter_Gzip(A)/=0 or else Filter_XZ(A)/=0 or else Filter_Zstd(A)/=0
        or else Filter_Bzip2(A)/=0 or else Format_CPIO(A)/=0
      then Status:=Unsupported; Cleanup; return; end if;
      if Open_FD(A,int(MC_FS.Native(F)),65_536)/=0 then Status:=Corrupt; Cleanup; return; end if;
      loop
         MC_Clock.Boottime_Milliseconds(Now,Status); if Status/=OK then Cleanup; return; end if;
         if Now>=Deadline then Status:=Stale; Cleanup; return; end if;
         RC:=Next_Header(A,E'Access); exit when RC=1; -- ARCHIVE_EOF
         if RC/=0 then Status:=Corrupt; Cleanup; return; end if;
         declare Raw : constant String:=Bounded(Pathname(E));
                 Path : constant String:=(if Raw'Length>2 and then Raw(1..2)="./" then Raw(3..Raw'Last) else Raw);
         begin Index:=Pkg_Payload_Map.Find(Map,Path); end;
         if Index=0 or else Seen(Index) or else Map.Files(Index).Ghost then Status:=Corrupt; Cleanup; return; end if;
         Seen(Index):=True;
         if Hardlink(E)/=Null_Ptr or else Sparse_Count(E)/=0 then Status:=Unsupported; Cleanup; return; end if;
         if (Word(Mode(E)) and 8#7777#)/=Map.Files(Index).Mode then Status:=Corrupt; Cleanup; return; end if;
         case Map.Files(Index).Kind is
            when Pkg_File_Plan.Regular =>
               if (Word(Mode(E)) and 8#170000#)/=8#100000# or else Size(E)<0
                 or else Counter(Size(E))/=Map.Files(Index).Size then Status:=Corrupt; Cleanup; return; end if;
               if Map.Files(Index).Size>32*1024*1024*1024-Total then Status:=Exhausted; Cleanup; return; end if;
               Total:=Total+Map.Files(Index).Size;
               MC_Store.Begin_Write(S,Map.Files(Index).Content,Map.Files(Index).Size,W,Status);
               if Status/=OK then Cleanup; return; end if;
               loop
                  MC_Clock.Boottime_Milliseconds(Now,Status);
                  if Status/=OK or else Now>=Deadline then Status:=Stale; Cleanup; return; end if;
                  N:=Read_Data(A,B'Address,B'Length); exit when N=0;
                  if N<0 or else N>long(B'Length) then Status:=Corrupt; Cleanup; return; end if;
                  MC_Store.Write_Chunk(W,B(1..Natural(N)),Status); if Status/=OK then Cleanup; return; end if;
               end loop;
               MC_Store.Finish_Write(S,W,Status); if Status/=OK then Cleanup; return; end if;
            when Pkg_File_Plan.Directory =>
               if (Word(Mode(E)) and 8#170000#)/=8#040000# then Status:=Corrupt; Cleanup; return; end if;
            when Pkg_File_Plan.Symbolic_Link =>
               if (Word(Mode(E)) and 8#170000#)/=8#120000# then Status:=Corrupt; Cleanup; return; end if;
               declare Text : constant String:=Bounded(Symlink(E)); Data : Bytes(1..Text'Length); begin
                  if Text/=MC_Text.Image(Map.Files(Index).Link_Target) then Status:=Corrupt; Cleanup; return; end if;
                  for J in Text'Range loop Data(J):=Byte(Character'Pos(Text(J))); end loop;
                  MC_Store.Put(S,Data,D,Status);
                  if Status/=OK or else D/=Map.Files(Index).Content then Status:=Corrupt; Cleanup; return; end if;
               end;
            when others => Status:=Unsupported; Cleanup; return;
         end case;
      end loop;
      for I in 1..Map.Count loop
         if not Map.Files(I).Ghost and then not Seen(I) then Status:=Corrupt; Cleanup; return; end if;
      end loop;
      Cleanup; Status:=OK;
   exception when others => Cleanup; Status:=IO_Error;
   end Stage;
end Pkg_Archive;
