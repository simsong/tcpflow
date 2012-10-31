/*
 * http://stackoverflow.com/questions/10467711/c-write-in-the-middle-of-a-binary-file-without-overwriting-any-existing-content
 */


#include <sys/stat.h>
#include <unistd.h>

enum { BUFFERSIZE = 64 * 1024 };

#define MIN(x, y) (((x) < (y)) ? (x) : (y))

/*
off_t   is signed
ssize_t is signed
size_t  is unsigned

off_t   for lseek() offset and return
size_t  for read()/write() length
ssize_t for read()/write() return
off_t   for st_size
*/

static int extend_file_and_insert(int fd, off_t offset, char const *insert, size_t inslen)
{
    char buffer[BUFFERSIZE];
    struct stat sb;
    int rc = -1;

    if (fstat(fd, &sb) == 0)
    {
        if (sb.st_size > offset)
        {
            /* Move data after offset up by inslen bytes */
            size_t bytes_to_move = sb.st_size - offset;
            off_t read_end_offset = sb.st_size; 
            while (bytes_to_move != 0)
            {
                ssize_t bytes_this_time = MIN(BUFFERSIZE, bytes_to_move);
                ssize_t rd_off = read_end_offset - bytes_this_time;
                ssize_t wr_off = rd_off + inslen;
                lseek(fd, rd_off, SEEK_SET);
                if (read(fd, buffer, bytes_this_time) != bytes_this_time)
                    return -1;
                lseek(fd, wr_off, SEEK_SET);
                if (write(fd, buffer, bytes_this_time) != bytes_this_time)
                    return -1;
                bytes_to_move -= bytes_this_time;
            }   
        }   
        lseek(fd, offset, SEEK_SET);
        write(fd, insert, inslen);
        rc = 0;
    }   
    return rc;
}
