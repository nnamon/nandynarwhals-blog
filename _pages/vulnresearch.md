---
layout: archive
permalink: /vulnresearch/
title: "Vulnerability Research"
header:
  overlay_image: /assets/images/vulnresearch-splash.jpg
  overlay_filter: 0.5
  caption: "Photo credit: Teresa Kluge on Unsplash"
excerpt: "Some of the vulnerability research findings I have discovered."
author_profile: true
---

Under construction.

{% include base_path %}
{% include group-by-array collection=site.posts field="tags" %}

{% for tag in group_names %}
  {% if tag == "vulnresearch" %}
    {% assign posts = group_items[forloop.index0] %}
    {% for post in posts %}
      {% include archive-single.html %}
    {% endfor %}
  {% endif %}
{% endfor %}
