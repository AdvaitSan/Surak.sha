"use client";

import { Button } from "@/components/ui/button";
import { ArrowRight, Shield, FileSearch, Activity, Lock, Cpu, Zap, Check } from "lucide-react";
import Link from "next/link";
import { useState, useEffect } from "react";

export default function Home() {
  const [scrolled, setScrolled] = useState(false);

  // Add scroll event listener to detect when page is scrolled
  useEffect(() => {
    const handleScroll = () => {
      setScrolled(window.scrollY > 10);
    };

    window.addEventListener('scroll', handleScroll);
    return () => window.removeEventListener('scroll', handleScroll);
  }, []);

  return (
    <div className="min-h-screen bg-background overflow-hidden -mt-20">
      {/* <header className={`fixed top-0 left-0 right-0 z-50 transition-all duration-300 ${scrolled ? "bg-background/95 shadow-md backdrop-blur-sm py-3" : "bg-transparent py-5"}`}>
        <div className="container mx-auto px-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <Shield className="w-6 h-6 text-primary" />
            <span className="font-bold text-xl">ShieldAI</span>
          </div>

          <nav className="hidden md:flex items-center gap-8">
            <Link href="/dashboard" className="text-muted-foreground hover:text-primary transition-colors">Dashboard</Link>
            <Link href="/upload" className="text-muted-foreground hover:text-primary transition-colors">Upload File</Link>
            <Link href="/about" className="text-muted-foreground hover:text-primary transition-colors">About Us</Link>
            <Link href="/docs" className="text-muted-foreground hover:text-primary transition-colors">Documentation</Link>
          </nav>

          <div className="flex items-center gap-3">
            <Link href="/login">
              <Button variant="ghost" size="sm">Log In</Button>
            </Link>
            <Link href="/signup">
              <Button size="sm" className="bg-primary hover:bg-primary/90">Sign Up</Button>
            </Link>
          </div>
        </div>
      </header> */}

      {/* Animated background elements */}
      <div className="fixed inset-0 -z-10">
        <div className="absolute top-0 left-0 w-1/3 h-1/3 bg-primary/10 rounded-full blur-3xl animate-pulse"></div>
        <div className="absolute bottom-0 right-0 w-1/3 h-1/3 bg-accent/10 rounded-full blur-3xl animate-pulse delay-1000"></div>
        <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-1/2 h-1/2 bg-secondary/5 rounded-full blur-3xl animate-pulse delay-500"></div>
      </div>

      <main className="container mx-auto px-4">
        {/* Hero Section */}
        <section className="pt-40 pb-24 flex flex-col md:flex-row md:items-center gap-12">
          <div className="flex-1 space-y-6">
            <div className="inline-flex items-center gap-2 bg-primary/10 text-primary px-4 py-2 rounded-full font-medium text-sm mb-4">
              <Zap className="w-4 h-4" />
              Next-Gen Security Solution
            </div>

            <h1 className="text-5xl md:text-6xl lg:text-7xl font-bold tracking-tighter leading-tight">
              <span className="bg-clip-text text-transparent bg-gradient-to-r from-primary via-secondary to-accent animate-gradient">
                AI-Powered
              </span>
              <br />
              <span className="text-foreground">Malware</span>
              <br />
              <span className="bg-clip-text text-transparent bg-gradient-to-r from-accent via-primary to-secondary animate-gradient">
                Detection
              </span>
            </h1>

            <p className="text-lg md:text-xl text-muted-foreground max-w-xl leading-relaxed">
              Advanced threat detection system capable of identifying both known and unknown
              malware in real-time, powered by state-of-the-art AI/ML technology.
            </p>

            <div className="flex flex-col sm:flex-row gap-4 pt-4">
              <Link href="/dashboard">
                <Button size="lg" className="w-full sm:w-auto text-lg group bg-primary hover:bg-primary/90 px-8">
                  Dashboard
                  <ArrowRight className="ml-2 w-5 h-5 group-hover:translate-x-1 transition-transform" />
                </Button>
              </Link>
              <Link href="/upload">
                <Button size="lg" variant="outline" className="w-full sm:w-auto text-lg group px-8">
                  Scan a File
                </Button>
              </Link>
            </div>

            <div className="flex items-center gap-6 pt-6">
              <div className="flex -space-x-3">
                <div className="w-8 h-8 rounded-full bg-primary/20 flex items-center justify-center text-primary text-xs font-bold">5k+</div>
                <div className="w-8 h-8 rounded-full bg-secondary/20 flex items-center justify-center text-secondary text-xs font-bold">4.9</div>
                <div className="w-8 h-8 rounded-full bg-accent/20 flex items-center justify-center text-accent text-xs font-bold">24/7</div>
              </div>
              <p className="text-md font-bold text-muted-foreground">Think-{'>'}Code-{'>'}Contribute</p>
            </div>
          </div>

          <div className="flex-1 relative">
            <div className="absolute -inset-4 rounded-full bg-gradient-to-r from-primary via-secondary to-accent blur-xl opacity-75 animate-pulse"></div>
            <div className="relative bg-card/30 p-8 rounded-2xl backdrop-blur-sm border border-primary/20 aspect-square max-w-md mx-auto flex items-center justify-center overflow-hidden">
              {/* Animated background grid */}
              <div className="absolute inset-0 grid grid-cols-10 grid-rows-10">
                {[...Array(100)].map((_, i) => (
                  <div
                    key={i}
                    className="border-[0.5px] border-primary/5"
                    style={{
                      opacity: Math.random() * 0.5 + 0.1
                    }}
                  ></div>
                ))}
              </div>

              {/* Animated concentric circles */}
              <div className="absolute inset-0 flex items-center justify-center">
                {[...Array(4)].map((_, i) => (
                  <div
                    key={i}
                    className="absolute rounded-full border border-primary/20"
                    style={{
                      width: `${(i + 1) * 20}%`,
                      height: `${(i + 1) * 20}%`,
                      animationDuration: `${8 + i * 4}s`,
                      animationDelay: `${i * 0.5}s`,
                      animation: 'pulse 8s infinite ease-in-out'
                    }}
                  ></div>
                ))}
              </div>

              {/* Digital scan effect */}
              <div className="absolute inset-0 overflow-hidden">
                <div className="absolute w-full h-8 bg-gradient-to-r from-transparent via-primary/20 to-transparent -translate-y-full animate-scan"></div>
              </div>

              {/* Central shield with glow effect */}
              <div className="relative z-10">
                <div className="absolute -inset-4 bg-primary/10 rounded-full blur-md animate-pulse"></div>
                <Shield className="w-32 h-32 text-primary relative z-10" />
              </div>

              {/* Floating data points */}
              <div className="absolute inset-0">
                {[...Array(5)].map((_, i) => (
                  <div
                    key={i}
                    className="absolute flex items-center gap-1"
                    style={{
                      top: `${20 + Math.random() * 60}%`,
                      left: `${10 + Math.random() * 80}%`,
                      transform: `scale(${0.7 + Math.random() * 0.5})`,
                      opacity: 0.7,
                      animation: `float ${5 + Math.random() * 5}s infinite ease-in-out`,
                      animationDelay: `${i * 0.8}s`
                    }}
                  >
                    <div className="h-1.5 w-1.5 rounded-full bg-primary"></div>
                    <div className="h-0.5 bg-primary/50" style={{ width: `${10 + Math.random() * 30}px` }}></div>
                  </div>
                ))}
              </div>
            </div>
          </div>

        </section>

        {/* Stats Section */}
        <section className="py-16">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-8">
            <div className="text-center">
              <h3 className="text-4xl font-bold bg-clip-text text-transparent bg-gradient-to-r from-primary to-secondary">99.8%</h3>
              <p className="text-muted-foreground mt-2">Detection Rate</p>
            </div>
            <div className="text-center">
              <h3 className="text-4xl font-bold bg-clip-text text-transparent bg-gradient-to-r from-secondary to-accent">500ms</h3>
              <p className="text-muted-foreground mt-2">Average Scan Time</p>
            </div>
            <div className="text-center">
              <h3 className="text-4xl font-bold bg-clip-text text-transparent bg-gradient-to-r from-accent to-primary">24/7</h3>
              <p className="text-muted-foreground mt-2">Continuous Protection</p>
            </div>
            <div className="text-center">
              <h3 className="text-4xl font-bold bg-clip-text text-transparent bg-gradient-to-r from-primary to-accent">5,000+</h3>
              <p className="text-muted-foreground mt-2">Enterprise Clients</p>
            </div>
          </div>
        </section>

        {/* Features Grid */}
        <section className="py-24">
          <div className="text-center mb-16">
            <h2 className="text-3xl md:text-4xl font-bold mb-4">Advanced Security Features</h2>
            <p className="text-lg text-muted-foreground max-w-2xl mx-auto">
              Our platform combines cutting-edge AI with robust security practices to deliver unmatched protection
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-8 w-full">
            <div className="group relative">
              <div className="absolute -inset-0.5 bg-gradient-to-r from-primary to-secondary rounded-xl blur opacity-30 group-hover:opacity-100 transition duration-1000"></div>
              <div className="relative p-8 bg-card/80 backdrop-blur-xl rounded-xl border border-white/10 h-full flex flex-col">
                <div className="bg-primary/10 p-3 rounded-lg w-fit mb-6">
                  <Cpu className="w-8 h-8 text-primary" />
                </div>
                <h3 className="text-xl font-semibold mb-3">AI/ML Detection Engine</h3>
                <p className="text-muted-foreground flex-grow">Leverages advanced machine learning algorithms to detect both known and zero-day threats with high accuracy.</p>
                <ul className="mt-6 space-y-2">
                  <li className="flex items-center gap-2">
                    <Check className="w-4 h-4 text-primary" />
                    <span className="text-sm">Deep neural networks</span>
                  </li>
                  <li className="flex items-center gap-2">
                    <Check className="w-4 h-4 text-primary" />
                    <span className="text-sm">Behavioral analysis</span>
                  </li>
                  <li className="flex items-center gap-2">
                    <Check className="w-4 h-4 text-primary" />
                    <span className="text-sm">Continual learning</span>
                  </li>
                </ul>
              </div>
            </div>

            <div className="group relative">
              <div className="absolute -inset-0.5 bg-gradient-to-r from-secondary to-accent rounded-xl blur opacity-30 group-hover:opacity-100 transition duration-1000"></div>
              <div className="relative p-8 bg-card/80 backdrop-blur-xl rounded-xl border border-white/10 h-full flex flex-col">
                <div className="bg-secondary/10 p-3 rounded-lg w-fit mb-6">
                  <Zap className="w-8 h-8 text-secondary" />
                </div>
                <h3 className="text-xl font-semibold mb-3">Real-time Analysis</h3>
                <p className="text-muted-foreground flex-grow">Scan files instantly and receive immediate threat assessments with detailed reporting.</p>
                <ul className="mt-6 space-y-2">
                  <li className="flex items-center gap-2">
                    <Check className="w-4 h-4 text-secondary" />
                    <span className="text-sm">Sub-second response time</span>
                  </li>
                  <li className="flex items-center gap-2">
                    <Check className="w-4 h-4 text-secondary" />
                    <span className="text-sm">Comprehensive reports</span>
                  </li>
                  <li className="flex items-center gap-2">
                    <Check className="w-4 h-4 text-secondary" />
                    <span className="text-sm">Threat visualization</span>
                  </li>
                </ul>
              </div>
            </div>

            <div className="group relative">
              <div className="absolute -inset-0.5 bg-gradient-to-r from-accent to-primary rounded-xl blur opacity-30 group-hover:opacity-100 transition duration-1000"></div>
              <div className="relative p-8 bg-card/80 backdrop-blur-xl rounded-xl border border-white/10 h-full flex flex-col">
                <div className="bg-accent/10 p-3 rounded-lg w-fit mb-6">
                  <Lock className="w-8 h-8 text-accent" />
                </div>
                <h3 className="text-xl font-semibold mb-3">Secure Platform</h3>
                <p className="text-muted-foreground flex-grow">Enterprise-grade security infrastructure ensuring your data remains protected.</p>
                <ul className="mt-6 space-y-2">
                  <li className="flex items-center gap-2">
                    <Check className="w-4 h-4 text-accent" />
                    <span className="text-sm">End-to-end encryption</span>
                  </li>
                  <li className="flex items-center gap-2">
                    <Check className="w-4 h-4 text-accent" />
                    <span className="text-sm">SOC2 compliance</span>
                  </li>
                  <li className="flex items-center gap-2">
                    <Check className="w-4 h-4 text-accent" />
                    <span className="text-sm">Secure data handling</span>
                  </li>
                </ul>
              </div>
            </div>
          </div>
        </section>

        {/* How It Works Section */}
        <section className="py-24">
          <div className="text-center mb-16">
            <h2 className="text-3xl md:text-4xl font-bold mb-4">How It Works</h2>
            <p className="text-lg text-muted-foreground max-w-2xl mx-auto">
              Our advanced AI malware detection system operates in three simple steps
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-6 relative">
            {/* Connection lines */}
            <div className="hidden md:block absolute top-1/2 left-0 w-full h-1 bg-gradient-to-r from-primary via-secondary to-accent -z-0"></div>

            <div className="relative bg-card/50 backdrop-blur-sm border border-white/10 rounded-xl p-8 text-center">
              <div className="absolute -top-6 left-1/2 -translate-x-1/2 w-12 h-12 rounded-full bg-primary flex items-center justify-center text-xl font-bold">1</div>
              <div className="pt-4">
                <FileSearch className="w-12 h-12 mx-auto mb-6 text-primary" />
                <h3 className="text-xl font-semibold mb-3">Upload File</h3>
                <p className="text-muted-foreground">Simply upload any suspicious file to our secure platform for immediate scanning.</p>
              </div>
            </div>

            <div className="relative bg-card/50 backdrop-blur-sm border border-white/10 rounded-xl p-8 text-center">
              <div className="absolute -top-6 left-1/2 -translate-x-1/2 w-12 h-12 rounded-full bg-secondary flex items-center justify-center text-xl font-bold">2</div>
              <div className="pt-4">
                <Activity className="w-12 h-12 mx-auto mb-6 text-secondary" />
                <h3 className="text-xl font-semibold mb-3">AI Analysis</h3>
                <p className="text-muted-foreground">Our advanced AI engine analyzes the file using multiple detection methods simultaneously.</p>
              </div>
            </div>

            <div className="relative bg-card/50 backdrop-blur-sm border border-white/10 rounded-xl p-8 text-center">
              <div className="absolute -top-6 left-1/2 -translate-x-1/2 w-12 h-12 rounded-full bg-accent flex items-center justify-center text-xl font-bold">3</div>
              <div className="pt-4">
                <Shield className="w-12 h-12 mx-auto mb-6 text-accent" />
                <h3 className="text-xl font-semibold mb-3">Get Results</h3>
                <p className="text-muted-foreground">Receive detailed threat analysis with actionable security recommendations.</p>
              </div>
            </div>
          </div>
        </section>

        {/* Call to Action */}
        <section className="py-24">
          <div className="relative w-full max-w-4xl mx-auto">
            <div className="absolute -inset-1 bg-gradient-to-r from-primary via-secondary to-accent rounded-2xl blur-xl opacity-30"></div>
            <div className="relative p-12 bg-card/80 backdrop-blur-xl rounded-2xl border border-white/10 text-center">
              <h2 className="text-3xl font-bold mb-4">Ready to enhance your security?</h2>
              <p className="text-lg text-muted-foreground mb-8 max-w-2xl mx-auto">
                Start protecting your systems from advanced malware threats today with our AI-powered detection platform.
              </p>
              <div className="flex flex-col sm:flex-row gap-4 justify-center">
                <Link href="/signup">
                  <Button size="lg" className="bg-primary hover:bg-primary/90 px-8 text-lg">
                    Create Free Account
                  </Button>
                </Link>
                <Link href="/demo">
                  <Button size="lg" variant="outline" className="px-8 text-lg">
                    Request Demo
                  </Button>
                </Link>
              </div>
            </div>
          </div>
        </section>
      </main>
    </div>
  );
}
