import gflags
import logging

FLAGS = gflags.FLAGS

gflags.DEFINE_string("tld_list_dir", "/tmp", "Stores top level domains list,"
                     " so it doesn't have to be fetched every run")

TLD_LIST_ADDR = "https://publicsuffix.org/list/effective_tld_names.dat"

class TLDList(object):
    """Contains list of top-level domains"""
    def __init__(self, tld_dir=FLAGS.tld_list_dir, tld_file_name="tld_list"):
        tld_file = '/'.join((tld_dir, tld_file_name))
        try:
            with open(tld_file, 'r') as f:
                raw_list = f.read()
        except IOError:
            logging.warning("Couldn't open file with top level domains")
        lines = unicode(raw_list, 'utf-8').splitlines()
        lines = lines[0:lines.index('// ===END ICANN DOMAINS===')]
        lines = filter(
            lambda line: not line.startswith('//') and not len(line) == 0,
            lines)
        lines = [line.split('.') for line in lines]
        self.tld_tree = {}
        for tld in lines:
            sub_tree = self.tld_tree
            for part in reversed(tld):
                if part.startswith('*'):
                   sub_tree['*'] = []
                elif part.startswith('!'):
                    sub_tree['*'].append(part[1:])
                elif part not in sub_tree:
                    sub_tree[part] = {}
                    sub_tree = sub_tree[part]
                else:
                    sub_tree = sub_tree[part]

    def match(self, address):
        """Matches address to the list.
        Returns:
            matching tld or None."""
        parts = address.split('.')
        best = []
        sub_tree = self.tld_tree
        for part in reversed(parts):
            if part in sub_tree:
                best.append(part)
                sub_tree = sub_tree[part]
            elif part not in sub_tree and '*' not in sub_tree:
                break
            elif '*' in sub_tree:
                for exception in sub_tree['*']:
                    if part == exception:
                        break
                    else:
                        best.append(part)
                # wildcard means that we can't go deeper
                break
        if best:
            best = '.'.join(reversed(best))
        else:
            best = None
        return best

    def match_idna(self, address):
        """Decodes address from idna and then matches to the list.
        Returns:
            matching tld or None."""
        try:
            idna = address.decode('idna')
            return self.match(idna)
        except:
            return None
