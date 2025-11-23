class FeedbacksController < ApplicationController
  # Simple in-memory store for demo/CTF purposes (non-persistent)
  @@submissions = []

  def new
    @submissions = @@submissions
  end

  def create
    name = params[:name].to_s
    feedback = params[:feedback].to_s

    # Store raw values intentionally; name will be rendered unsanitized in the view for XSS challenge
    @@submissions << {
      name: name,
      feedback: feedback,
      created_at: Time.current
    }

    redirect_to feedback_path, notice: "Mulțumim pentru feedback!"
  end
end

