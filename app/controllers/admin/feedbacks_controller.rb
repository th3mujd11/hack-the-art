module Admin
  class FeedbacksController < ApplicationController
    helper ::FeedbacksHelper
    before_action :maybe_require_admin!

    def index
      @submissions = ::FeedbacksController.class_variable_get(:@@submissions)
      @flag = ENV["HACKTHEART_FLAG"] || "HTA{dev-flag}"
    end

    private
    # If ADMIN_TOKEN is set, require matching cookie; otherwise leave public for testing
    def maybe_require_admin!
      expected = ENV["ADMIN_TOKEN"].to_s
      return if expected.empty?
      token = cookies[:admin_token]
      head :not_found unless ActiveSupport::SecurityUtils.secure_compare(token.to_s, expected)
    end
  end
end
