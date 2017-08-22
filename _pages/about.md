---
title: "Welcome"
layout: splash
permalink: /about/
header:
  overlay_color: "#000"
  overlay_filter: "0.5"
  overlay_image: /assets/images/about-splash.jpg
  cta_label: "My Github"
  cta_url: "https://github.com/nnamon/"
  caption: "Photo credit: Sam Ferrara on [**Unsplash**](https://unsplash.com)"
excerpt: "Welcome to the Nandy Narwhals CTF Team blog. It is home to my personal
          team, **Nandy Narwhals** as well as the **Dystopian Narwhals**, a merger with
          the Dystopian Knights. I am also part of the **NUS Greyhats**, an academic
          team at the National University of Singapore."
intro:
  - excerpt: "I am currently a student studying information security at the
             National University of Singapore and I post writeups on CTF
             challenges, information security tutorials, as well as my
             independent vulnerability research findings."
feature_row:
  - image_path: assets/images/about-writeups.jpg
    alt: "Writeups"
    title: "Writeups"
    excerpt: "Mostly detailed writeups on my solutions to CTF problems I have
             solved or written."
    btn_label: "Read Writeups"
    btn_class: "btn--inverse"
    url: "/writeups/"
  - image_path: /assets/images/about-tutorials.jpg
    alt: "Tutorials"
    title: "Tutorials"
    excerpt: "Here are some tutorials and guides I have produced to teach
              information security concepts."
    url: "/tutorials/"
    btn_label: "Browse Tutorials"
    btn_class: "btn--inverse"
  - image_path: /assets/images/about-vulnresearch.jpg
    title: "Vulnerability Research"
    excerpt: "These are some of my vulnerability research findings I have found
              in my spare time."
    url: "/vulnresearch/"
    btn_label: "Browse Research"
    btn_class: "btn--inverse"
---

{% include feature_row id="intro" type="center" %}

{% include feature_row %}

