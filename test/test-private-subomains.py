import os
import subprocess
import time

# Directory for all generated files
BASE_DIR = "tmp"

# File from which CA configs are derived
DEFAULT_CA_CONF = "default_ca.conf"

def cat_files(out, *ins):
    out = open(out, "w+")
    for i in ins:
        out.write(open(i, "r").read())


def copy_file(out, inf, subst):
    txt = open(inf, "r").read()
    for s in subst:
        txt = txt.replace(s, subst[s])
    open(out, "w+").write(txt)


class CAManager(object):
    def __init__(self, directory, name):
        self.dir_ = directory
        self.name_ = name

    def local_file(self, name):
        return self.dir_ + "/" + name

    def ca_file(self, filetype):
        return self.dir_ + "/" + self.name_ + "." + filetype
        
    def database(self):
        return self.ca_file("database")

    def serial(self):
        return self.ca_file("serial")

    def config(self):
        return self.ca_file("conf")

    def setup_serial(self):
        open(self.serial(), "w+").write("0000000000000001")

    def cert_file(self, subject, ispre):
        if ispre:
            pre = ".pre"
        else:
            pre = ""
            
        return self.local_file(subject + pre + ".cert.pem")

    def ca_cert_file(self):
        return self.ca_file("cert.pem")

    @staticmethod
    def ext_file(ispre, isca, custom_ext):
        if custom_ext:
            assert not isca
            return custom_ext
        
        if ispre:
            conf = "precert.conf"
        else:
            conf = "cert.conf"
            
        if isca:
            conf = "ca-" + conf
            
        # not sure what config is used when !ispre and !isca
        assert ispre or isca
        
        return conf

    def setup(self):
        database = self.database()
        serial = self.serial()
        conf_file = self.config()
        
        open(database, "w+")
        open(database + ".attr", "w+")
        self.setup_serial()
        
        config = open(DEFAULT_CA_CONF, "r").read()
        config = config.replace("default_serial", serial)
        config = config.replace("default_database", database)
        open(conf_file, "w+").write(config)
        self.create_ca_cert()

    def create_ca_cert(self):
        self.create_cert(self.name_, isca=True)

    def request_cert(self, subject, ispre=False, isca=False, ext=None):
        subprocess.call(["openssl", "req",
                         "-new",
                         "-newkey", "rsa:1024",
                         "-keyout", self.key_file(subject),
                         "-out", self.csr_file(subject),
                         "-config", self.ext_file(ispre, isca, ext),
                         "-nodes"])

    def key_file(self, subject):
        return self.local_file(subject + ".key.pem")

    def csr_file(self, subject):
        return self.local_file(subject + ".csr")

    def issue_cert(self, subject, ispre=False, isca=False, ext=None, extensions=None):
        issuer = self.name_
        
        if issuer == subject:
            sign = ["-selfsign"]
        else:
            sign = ["-cert", self.ca_cert_file()]

        if extensions:
            extensions = ["-extensions", extensions]
        elif ispre:
            extensions = ["-extensions", "ct_ext"]
        else:
            extensions = ["-extensions", "v3_ca"]

        p = subprocess.Popen(["openssl", "ca",
                              "-in", self.local_file(subject + ".csr"),
                              "-keyfile", self.key_file(issuer),
                              "-config", self.config(),
                              "-outdir", self.dir_,
                              "-out", self.cert_file(subject, ispre),
                              "-extfile", self.ext_file(ispre, isca, ext)
                              ] + sign + extensions, stdin=subprocess.PIPE)
        p.communicate("y\ny\n")
        p.wait()

    def create_cert(self, subject, **kw):
        kw2 = {}
        for k in kw:
            if k != "extensions":
                kw2[k] = kw[k]
        self.request_cert(subject, **kw2)
        self.issue_cert(subject, **kw)

    def read_serial(self):
        return open(self.serial()).read()

    def write_serial(self, serial):
        open(self.serial(), "w+").write(serial)

    @staticmethod
    def read_cert_serial(cert):
        p = subprocess.Popen(["openssl", "x509",
                              "-in", cert,
                              "-serial",
                              "-noout"], stdout=subprocess.PIPE)
        p.wait()
        serial = p.stdout.read()
        assert(serial.startswith("serial="))
        return serial[7:]


class PreCAManager(CAManager):
    def __init__(self, directory, name):
        self.base_ca_ = CAManager(directory, name)
        super(PreCAManager, self).__init__(directory, name)

    def database(self):
        return self.ca_file("pre.database")

    def config(self):
        return self.ca_file("pre.conf")

    def setup(self):
        self.base_ca_.setup()
        super(PreCAManager, self).setup()

    def setup_serial(self):
        pass

    def create_ca_cert(self):
        subject = self.name_ + ".pre"
        self.base_ca_.create_cert(subject, ispre=True, isca=True)

    def create_embedded_cert(self, log, common_name):
        conf_file = self.local_file(common_name + ".pre.conf")

        copy_file(conf_file, "precert.conf",
                  { "0.organizationName=Certificate Transparency":
                    "0.organizationName=CT client\n0.commonName=" + common_name
                    })
        
        self.create_cert(common_name, ispre=True, ext=conf_file,
                        extensions="pre")

        bundle = self.local_file(common_name + ".pre.bundle.pem")
        cat_files(bundle,
                  self.cert_file(common_name, True),
                  self.cert_file(self.name_, False))

        sct_conf = self.local_file(common_name + ".sct.conf")
        copy_file(sct_conf, conf_file, {})

        log.run(self.base_ca_.ca_cert_file())

        log.upload(bundle, bundle + ".sct", sct_conf)

        log.kill()

        save_serial = self.base_ca_.read_serial()
        print "Saving serial", save_serial

        serial = self.read_cert_serial(bundle)
        print "Got serial", serial

        # Save CA's current serial 

        try:
            self.base_ca_.write_serial(serial)
            self.base_ca_.issue_cert(common_name, ext=sct_conf,
                                     extensions="embedded")
        finally:
            self.base_ca_.write_serial(save_serial)


class LogManager(object):
    def __init__(self, directory, name):
        self.dir_ = directory
        self.name_ = name

    def log_file(self, filetype):
        return self.dir_ + "/" + self.name_ + "." + filetype

    def public_key(self):
        return self.log_file("public-key.pem")

    def private_key(self):
        return self.log_file("key.pem")

    def db(self):
        return self.log_file("sqlite")
    
    def setup(self):
        subprocess.call(["openssl", "ecparam",
                         "-out", self.private_key(),
                         "-name", "secp256r1",
                         "-genkey"])
        subprocess.call(["openssl", "ec",
                         "-in", self.private_key(),
                         "-pubout",
                         "-out", self.public_key()])
        try:
            os.remove(self.db())
        except OSError:
            pass

    def server_url(self):
        return "localhost:8111"

    def run(self, trusted_cert):
        self.log_ = subprocess.Popen(["../cpp/server/ct-rfc-server",
                                      "--port=8111",
                                      "--key=" + self.private_key(),
                                      "--trusted_cert_file=" + trusted_cert,
                                      "--logtostderr=true",
                                      "--tree_signing_frequency_seconds=1",
                                      "--sqlite_db=" + self.db(),
                                      "-v=5"])
        time.sleep(2)

    def kill(self):
        self.log_.kill()

    def ct(self, *args):
        subprocess.call(["../cpp/client/ct", "--logtostderr"] + list(args))

    def upload(self, bundle, sct, conf):
        self.ct("upload",
                "--ct_server_submission=" + bundle,
                "--http_log",
                "--ct_server=" + self.server_url(),
                "--ct_server_public_key=" + self.public_key(),
                "--ct_server_response_out=" + sct,
                "--precert=true")

        self.ct("configure_proof",
                "--extensions_config_out=" + conf,
                "--sct_token=" + sct)

if not os.path.exists(BASE_DIR):
    os.makedirs(BASE_DIR)

ca = PreCAManager(BASE_DIR, "private-domains")
ca.setup()

log = LogManager(BASE_DIR, "ct-log")
log.setup()

ca.create_embedded_cert(log, "common")
