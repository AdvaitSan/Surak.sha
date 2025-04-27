"use client";

import { useState, useEffect } from "react";
import Link from "next/link";
import { Button } from "@/components/ui/button";
import { Shield } from "lucide-react";

export default function Navbar() {
  const [scrolled, setScrolled] = useState(false);

  useEffect(() => {
    const handleScroll = () => {
      setScrolled(window.scrollY > 10);
    };

    window.addEventListener("scroll", handleScroll);
    return () => window.removeEventListener("scroll", handleScroll);
  }, []);

  return (
    <header
      className={`fixed top-0 left-0 right-0 z-50 transition-all duration-300 ${
        scrolled ? "bg-background/95 shadow-md backdrop-blur-sm py-3" : "bg-transparent py-5"
      }`}
    >
      <div className="container mx-auto px-4 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Shield className="w-6 h-6 text-primary" />
          <Link href="/" className="text-4xl">सुरख.sha</Link>
        </div>

        <nav className="hidden md:flex items-center gap-8">
        <Link href="/upload" className="nav-link text-muted-foreground hover:text-primary transition-colors">
            Scanner
          </Link>
          <Link href="/report" className="nav-link text-muted-foreground hover:text-primary transition-colors">
            Report
          </Link>
          <Link href="/dynamic" className="nav-link text-muted-foreground hover:text-primary transition-colors">
            Dynamic
          </Link>
          <Link href="/dashboard" className="nav-link text-muted-foreground hover:text-primary transition-colors">
            Dashboard
          </Link>
        </nav>

        {/* <div className="flex items-center gap-3">
          <Link href="/login">
            <Button variant="ghost" size="sm">
              Log In
            </Button>
          </Link>
          <Link href="/signup">
            <Button size="sm" className="bg-primary hover:bg-primary/90">
              Sign Up
            </Button>
          </Link>
        </div> */}
      </div>
    </header>
  );
}
