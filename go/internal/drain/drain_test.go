package drain

import (
	"fmt"
	"testing"
)

func TestDrainBasics(t *testing.T) {
	d := New(TremorConfig())
	m := TremorMasker()
	a, ch := d.Add(m.Mask("Login failed user=alice ip=10.0.0.1 attempts=3"))
	if ch != ChangeCreated || a.ID != 1 {
		t.Fatalf("first message: %v %d", ch, a.ID)
	}
	b, ch := d.Add(m.Mask("Login failed user=bob ip=10.0.0.9 attempts=1"))
	if b.ID != 1 || ch != ChangeTemplateChanged || b.Template() != "Login failed <*> ip=<IP> attempts=<NUM>" {
		t.Fatalf("second message: id %d %v %q", b.ID, ch, b.Template())
	}
	if c, ch := d.Add(m.Mask("Login failed user=carol ip=10.1.1.1 attempts=4")); c.ID != 1 || ch != ChangeNone || c.Size != 3 {
		t.Fatalf("third message: %+v %v", c, ch)
	}
	if c, _ := d.Add("Disk full on /var"); c.ID != 2 {
		t.Fatal("different message joined an existing cluster")
	}
	if c, _ := d.Add(""); c.ID != 3 || c.Template() != "" {
		t.Fatal("empty message")
	}
	if c, _ := d.Add("   "); c.ID != 3 {
		t.Fatal("whitespace-only message should match the empty cluster")
	}
}

func TestDrainLRUEviction(t *testing.T) {
	cfg := TremorConfig()
	cfg.MaxClusters = 2
	d := New(cfg)
	d.Add("alpha one")
	d.Add("beta two three")
	d.Add("alpha one") // touch cluster 1: cluster 2 is now least recently used
	d.Add("gamma four five six")
	if d.Get(2) != nil || d.Get(1) == nil || d.Len() != 2 {
		t.Fatalf("expected cluster 2 evicted, live %d", d.Len())
	}
	if c, _ := d.Add("beta two three"); c.ID != 4 {
		t.Fatalf("evicted template came back with id %d, want a new id 4", c.ID)
	}
}

func TestDepthBelowThreePanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("no panic")
		}
	}()
	New(Config{Depth: 2})
}

func BenchmarkMaskAndAdd(b *testing.B) {
	d, m := New(TremorConfig()), TremorMasker()
	msgs := make([]string, 1000)
	for i := range msgs {
		msgs[i] = fmt.Sprintf("Payment authorized txn_%012x amount=%d.%02d INR merchant=m%d card <CARD> in %dms", i*7919, i%2500, i%100, i%4, i%300)
	}
	b.ReportAllocs()
	for i := 0; b.Loop(); i++ {
		d.Add(m.Mask(msgs[i%len(msgs)]))
	}
}

func TestMaskTokens(t *testing.T) {
	cases := map[string]string{
		"Login failed user=usr_c4f98b558772 ip=ip_fc5d33c6577d": "Login failed user=<USER> ip=<IP>",
		"from ip_4094b74257eb port 22":                          "from <IP> port 22",
		"zip_fc5d33c6577d ip_short ip_fc5d33c6577dz":            "zip_fc5d33c6577d ip_short ip_fc5d33c6577dz",
		"nothing here": "nothing here",
	}
	for in, want := range cases {
		if got := MaskTokens(in); got != want {
			t.Errorf("MaskTokens(%q) = %q, want %q", in, got, want)
		}
	}
}
